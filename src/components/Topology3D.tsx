import { useEffect, useRef, useState } from 'react';
import { Crosshair, Maximize2, RotateCw } from 'lucide-react';
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js';
import type { NetworkDevice, SecurityFinding } from '../types/network';
import { getDeviceHighestSeverity } from '../utils/auditEngine';
import { SeverityBadge } from './SeverityBadge';
import {
  buildHardwareNodeGroup,
  buildLinkConduit,
  createContactShadowTexture,
  createRadarFloorTexture,
  createSharedNodeAssets,
} from './three/networkModels';

interface Topology3DProps {
  devices: NetworkDevice[];
  findings: SecurityFinding[];
  selectedDeviceId: string | null;
  onSelectDevice: (deviceId: string) => void;
  isScanning: boolean;
  discoveredCount: number;
}

type CameraPreset = 'overview' | 'focus' | 'zenith';

const _targetCamPos = new THREE.Vector3();
const _targetLookAt = new THREE.Vector3();

function detectSoftwareWebGL(): boolean {
  try {
    const probeCanvas = document.createElement('canvas');
    const gl = probeCanvas.getContext('webgl2');
    if (!gl) return true;
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    const param = ext ? ext.UNMASKED_RENDERER_WEBGL : gl.RENDERER;
    const gpu = String(gl.getParameter(param) ?? '');
    gl.getExtension('WEBGL_lose_context')?.loseContext();
    return /SwiftShader|llvmpipe|softpipe|Software|Basic Render/i.test(gpu);
  } catch {
    return true;
  }
}

export function Topology3D({
  devices,
  findings,
  selectedDeviceId,
  onSelectDevice,
  isScanning,
  discoveredCount,
}: Topology3DProps) {
  const mountRef = useRef<HTMLDivElement | null>(null);
  const onSelectRef = useRef(onSelectDevice);
  onSelectRef.current = onSelectDevice;

  const [autoRotate, setAutoRotate] = useState(false);
  const [cameraPreset, setCameraPreset] = useState<CameraPreset>('overview');
  const [webglError, setWebglError] = useState(false);
  const [hoveredDeviceId, setHoveredDeviceId] = useState<string | null>(null);

  const autoRotateRef = useRef(autoRotate);
  autoRotateRef.current = autoRotate;

  const selectedIdRef = useRef(selectedDeviceId);
  selectedIdRef.current = selectedDeviceId;

  const presetTriggerRef = useRef<((preset: CameraPreset) => void) | null>(null);
  const sceneRebuildRef = useRef<(() => void) | null>(null);
  const selectionUpdateRef = useRef<(() => void) | null>(null);

  const visibleDevices = isScanning ? devices.slice(0, Math.max(1, discoveredCount)) : devices;
  const visibleDevicesRef = useRef(visibleDevices);
  visibleDevicesRef.current = visibleDevices;

  const findingsRef = useRef(findings);
  findingsRef.current = findings;

  // Mount Three.js WebGL context once
  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const isSoftwareGl = detectSoftwareWebGL();
    let renderer: THREE.WebGLRenderer;

    try {
      renderer = new THREE.WebGLRenderer({
        antialias: !isSoftwareGl,
        powerPreference: 'high-performance',
      });
    } catch {
      setWebglError(true);
      return;
    }

    const canvas = renderer.domElement;
    const onContextLost = (e: Event) => {
      e.preventDefault();
      setWebglError(true);
    };
    const onContextRestored = () => {
      setWebglError(false);
    };
    canvas.addEventListener('webglcontextlost', onContextLost);
    canvas.addEventListener('webglcontextrestored', onContextRestored);

    const initialW = container.clientWidth || 640;
    const initialH = container.clientHeight || 380;
    let lastW = initialW;
    let lastH = initialH;

    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.1;
    renderer.setPixelRatio(isSoftwareGl ? 1 : Math.min(window.devicePixelRatio, 2));
    renderer.shadowMap.enabled = !isSoftwareGl;
    renderer.shadowMap.type = THREE.PCFSoftShadowMap;
    renderer.setSize(initialW, initialH);
    container.innerHTML = '';
    container.appendChild(canvas);

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0b1120);
    scene.fog = new THREE.FogExp2(0x0b1120, 0.032);

    // Studio IBL environment map
    const pmremGenerator = new THREE.PMREMGenerator(renderer);
    const envRT = pmremGenerator.fromScene(new RoomEnvironment(), 0.04);
    scene.environment = envRT.texture;
    pmremGenerator.dispose();

    const camera = new THREE.PerspectiveCamera(44, initialW / initialH, 0.1, 100);
    camera.position.set(0, 8.2, 11.2);

    const controls = new OrbitControls(camera, canvas);
    controls.enableDamping = !isSoftwareGl;
    controls.dampingFactor = 0.06;
    controls.maxPolarAngle = Math.PI * 0.45;
    controls.minDistance = 4;
    controls.maxDistance = 24;
    controls.target.set(0, 0.5, 0);

    // Warm Key + Cool Hemisphere Fill
    const hemiLight = new THREE.HemisphereLight(0x38bdf8, 0x0f172a, 0.85);
    scene.add(hemiLight);

    const keyLight = new THREE.DirectionalLight(0xfff1e0, 1.85);
    keyLight.position.set(7, 12, 6);
    if (!isSoftwareGl) {
      keyLight.castShadow = true;
      keyLight.shadow.mapSize.set(1024, 1024);
      keyLight.shadow.camera.left = -10;
      keyLight.shadow.camera.right = 10;
      keyLight.shadow.camera.top = 10;
      keyLight.shadow.camera.bottom = -10;
      keyLight.shadow.bias = -0.0005;
      keyLight.shadow.normalBias = 0.02;
    }
    scene.add(keyLight);

    const rimLight = new THREE.DirectionalLight(0x06b6d4, 0.9);
    rimLight.position.set(-8, 6, -7);
    scene.add(rimLight);

    // Grounded Cyber Radar Floor
    const maxAniso = renderer.capabilities.getMaxAnisotropy();
    const floorTex = createRadarFloorTexture(maxAniso);
    const floorMat = new THREE.MeshStandardMaterial({
      map: floorTex,
      color: 0xffffff,
      roughness: 0.85,
      metalness: 0.15,
    });
    const floorMesh = new THREE.Mesh(new THREE.CircleGeometry(14, 48), floorMat);
    floorMesh.rotation.x = -Math.PI / 2;
    floorMesh.receiveShadow = true;
    scene.add(floorMesh);

    const shadowTex = createContactShadowTexture();
    const sharedAssets = createSharedNodeAssets(shadowTex);

    // Dynamic topology group + selection halo
    const topologyGroup = new THREE.Group();
    scene.add(topologyGroup);

    const selectionRingGeo = new THREE.RingGeometry(1.18, 1.32, 32);
    const selectionRingMat = new THREE.MeshBasicMaterial({
      color: 0x22d3ee,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.92,
      depthWrite: false,
    });
    const selectionRing = new THREE.Mesh(selectionRingGeo, selectionRingMat);
    selectionRing.rotation.x = -Math.PI / 2;
    selectionRing.position.y = 0.025;
    scene.add(selectionRing);

    const nodePositionMap = new Map<string, THREE.Vector3>();
    let interactables: THREE.Mesh[] = [];
    const disposableItems: Array<{ dispose: () => void }> = [];

    const clearDynamicTopology = () => {
      for (const item of disposableItems) {
        item.dispose();
      }
      disposableItems.length = 0;
      topologyGroup.clear();
      interactables = [];
      nodePositionMap.clear();
    };

    const updateSelectionRing = (shouldRender = true) => {
      const activeId = selectedIdRef.current;
      const pos = activeId ? nodePositionMap.get(activeId) : undefined;
      if (pos) {
        selectionRing.visible = true;
        selectionRing.position.set(pos.x, 0.025, pos.z);
      } else {
        selectionRing.visible = false;
      }
      if (shouldRender) {
        requestRender();
      }
    };

    const rebuildTopology = (shouldRender = true) => {
      clearDynamicTopology();
      const devs = visibleDevicesRef.current;
      const curFindings = findingsRef.current;
      if (devs.length === 0) return;

      const gateway = devs.find((d) => d.isGateway) ?? devs[0];
      const satellites = devs.filter((d) => d.id !== gateway.id);

      const gwPos = new THREE.Vector3(0, 0, 0);
      nodePositionMap.set(gateway.id, gwPos);

      const gwRisk = getDeviceHighestSeverity(gateway, curFindings);
      const gwBuilt = buildHardwareNodeGroup(gateway, gwRisk, sharedAssets, isSoftwareGl);
      gwBuilt.group.position.copy(gwPos);
      topologyGroup.add(gwBuilt.group);
      interactables.push(gwBuilt.hitbox);
      disposableItems.push(gwBuilt.ringMaterial);

      const radius = satellites.length <= 3 ? 4.2 : 5.2;
      satellites.forEach((dev, idx) => {
        const angle = (idx / Math.max(1, satellites.length)) * Math.PI * 2 - Math.PI / 4;
        const pos = new THREE.Vector3(Math.cos(angle) * radius, 0, Math.sin(angle) * radius);
        nodePositionMap.set(dev.id, pos);

        const risk = getDeviceHighestSeverity(dev, curFindings);
        const built = buildHardwareNodeGroup(dev, risk, sharedAssets, isSoftwareGl);
        built.group.position.copy(pos);
        built.group.lookAt(0, 0, 0);
        topologyGroup.add(built.group);
        interactables.push(built.hitbox);
        disposableItems.push(built.ringMaterial);

        const conduit = buildLinkConduit(gwPos, pos, risk);
        topologyGroup.add(conduit);
        disposableItems.push(conduit.geometry, conduit.material as THREE.Material);
      });

      updateSelectionRing(false);
      if (shouldRender) {
        requestRender();
      }
    };

    // Camera transition state
    let transitionActive = false;
    const applyCameraPreset = (preset: CameraPreset) => {
      if (preset === 'overview') {
        _targetCamPos.set(0, 8.2, 11.2);
        _targetLookAt.set(0, 0.5, 0);
      } else if (preset === 'zenith') {
        _targetCamPos.set(0, 14.5, 0.8);
        _targetLookAt.set(0, 0, 0);
      } else {
        const activeId = selectedIdRef.current;
        const nodePos = (activeId && nodePositionMap.get(activeId)) || new THREE.Vector3(0, 0, 0);
        _targetCamPos.set(nodePos.x + 3.2, 3.8, nodePos.z + 4.4);
        _targetLookAt.set(nodePos.x, 0.65, nodePos.z);
      }
      transitionActive = true;
      requestRender();
    };

    presetTriggerRef.current = applyCameraPreset;
    sceneRebuildRef.current = () => rebuildTopology(true);
    selectionUpdateRef.current = () => updateSelectionRing(true);

    // Render scheduling (on-demand + smooth transition + optional autoRotate)
    let rafId = 0;
    let timeoutId = 0;
    let disposed = false;
    let renderBusy = false;
    let renderDirty = false;
    let lastTime = performance.now();

    function afterDraw(cb: () => void) {
      const gl = renderer.getContext() as WebGL2RenderingContext;
      const sync = gl.fenceSync(gl.SYNC_GPU_COMMANDS_COMPLETE, 0);
      gl.flush();
      const poll = () => {
        if (disposed) {
          if (sync) gl.deleteSync(sync);
          return;
        }
        const state = sync && gl.getSyncParameter(sync, gl.SYNC_STATUS);
        if (state === gl.UNSIGNALED) {
          timeoutId = window.setTimeout(poll, 5);
        } else {
          if (sync) gl.deleteSync(sync);
          timeoutId = window.setTimeout(cb, 80);
        }
      };
      timeoutId = window.setTimeout(poll, 5);
    }

    function requestRender() {
      if (disposed) return;
      if (renderBusy) {
        renderDirty = true;
        return;
      }
      renderBusy = true;
      rafId = window.requestAnimationFrame(() => {
        if (disposed) return;
        renderDirty = false;
        const now = performance.now();
        const dt = Math.min(0.1, (now - lastTime) / 1000);
        lastTime = now;

        if (transitionActive) {
          camera.position.x = THREE.MathUtils.damp(camera.position.x, _targetCamPos.x, 6.5, dt);
          camera.position.y = THREE.MathUtils.damp(camera.position.y, _targetCamPos.y, 6.5, dt);
          camera.position.z = THREE.MathUtils.damp(camera.position.z, _targetCamPos.z, 6.5, dt);
          controls.target.x = THREE.MathUtils.damp(controls.target.x, _targetLookAt.x, 6.5, dt);
          controls.target.y = THREE.MathUtils.damp(controls.target.y, _targetLookAt.y, 6.5, dt);
          controls.target.z = THREE.MathUtils.damp(controls.target.z, _targetLookAt.z, 6.5, dt);

          if (
            camera.position.distanceTo(_targetCamPos) < 0.04 &&
            controls.target.distanceTo(_targetLookAt) < 0.04
          ) {
            transitionActive = false;
          }
        }

        controls.autoRotate = !isSoftwareGl && autoRotateRef.current;
        controls.autoRotateSpeed = 1.4;
        controls.update();
        renderer.render(scene, camera);

        const done = () => {
          if (disposed) return;
          renderBusy = false;
          if (renderDirty || transitionActive || (!isSoftwareGl && autoRotateRef.current)) {
            requestRender();
          }
        };

        if (isSoftwareGl) {
          afterDraw(done);
        } else {
          done();
        }
      });
    }

    // Cancel camera animation when user interacts directly
    const onControlStart = () => {
      transitionActive = false;
    };
    const onControlChange = () => {
      requestRender();
    };
    controls.addEventListener('start', onControlStart);
    controls.addEventListener('change', onControlChange);

    // Raycasting on layer 1 proxy hitboxes
    const raycaster = new THREE.Raycaster();
    raycaster.layers.set(1);
    const pointer = new THREE.Vector2();
    let lastMoveTime = 0;

    const updatePointer = (e: PointerEvent) => {
      const rect = canvas.getBoundingClientRect();
      pointer.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
    };

    let pointerDownX = 0;
    let pointerDownY = 0;
    const onPointerDown = (e: PointerEvent) => {
      pointerDownX = e.clientX;
      pointerDownY = e.clientY;
    };

    const onPointerUp = (e: PointerEvent) => {
      if (Math.hypot(e.clientX - pointerDownX, e.clientY - pointerDownY) > 6) return;
      updatePointer(e);
      raycaster.setFromCamera(pointer, camera);
      const hits = raycaster.intersectObjects(interactables, false);
      if (hits.length > 0) {
        const hitId = hits[0].object.userData?.deviceId;
        if (typeof hitId === 'string') {
          onSelectRef.current(hitId);
        }
      }
    };

    const onPointerMove = (e: PointerEvent) => {
      const now = Date.now();
      if (now - lastMoveTime < 60) return;
      lastMoveTime = now;

      updatePointer(e);
      raycaster.setFromCamera(pointer, camera);
      const hits = raycaster.intersectObjects(interactables, false);
      if (hits.length > 0) {
        const hitId = hits[0].object.userData?.deviceId ?? null;
        canvas.style.cursor = 'pointer';
        setHoveredDeviceId(hitId);
      } else {
        canvas.style.cursor = 'grab';
        setHoveredDeviceId(null);
      }
    };

    canvas.addEventListener('pointerdown', onPointerDown);
    canvas.addEventListener('pointerup', onPointerUp);
    canvas.addEventListener('pointermove', onPointerMove);

    const handleResize = () => {
      if (!container) return;
      const w = container.clientWidth;
      const h = container.clientHeight;
      if (w <= 0 || h <= 0 || (w === lastW && h === lastH)) return;
      lastW = w;
      lastH = h;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
      if (!renderBusy) {
        renderer.render(scene, camera);
      } else {
        requestRender();
      }
    };

    const resizeObserver = new ResizeObserver(handleResize);
    resizeObserver.observe(container);

    if (!isSoftwareGl) {
      renderer.compile(scene, camera);
    }

    rebuildTopology(false);
    controls.update();
    renderer.render(scene, camera);

    return () => {
      disposed = true;
      window.cancelAnimationFrame(rafId);
      window.clearTimeout(timeoutId);
      resizeObserver.disconnect();
      controls.removeEventListener('start', onControlStart);
      controls.removeEventListener('change', onControlChange);
      controls.dispose();
      canvas.removeEventListener('pointerdown', onPointerDown);
      canvas.removeEventListener('pointerup', onPointerUp);
      canvas.removeEventListener('pointermove', onPointerMove);
      canvas.removeEventListener('webglcontextlost', onContextLost);
      canvas.removeEventListener('webglcontextrestored', onContextRestored);

      clearDynamicTopology();
      floorMesh.geometry.dispose();
      floorMat.dispose();
      floorTex.dispose();
      shadowTex.dispose();
      sharedAssets.chassisMat.dispose();
      sharedAssets.trimMat.dispose();
      sharedAssets.screenMat.dispose();
      sharedAssets.shadowMat.dispose();
      sharedAssets.hitboxMat.dispose();
      sharedAssets.shadowGeo.dispose();
      selectionRingGeo.dispose();
      selectionRingMat.dispose();
      envRT.dispose();
      renderer.dispose();
    };
  }, []);

  // Rebuild 3D hardware nodes when audit devices/findings change (skip initial mount)
  const mountedTopologyRef = useRef(false);
  useEffect(() => {
    if (!mountedTopologyRef.current) {
      mountedTopologyRef.current = true;
      return;
    }
    sceneRebuildRef.current?.();
  }, [devices, findings, discoveredCount, isScanning]);

  // Update selection ring without tearing down scene (skip initial mount)
  const mountedSelectionRef = useRef(false);
  useEffect(() => {
    if (!mountedSelectionRef.current) {
      mountedSelectionRef.current = true;
      return;
    }
    selectionUpdateRef.current?.();
  }, [selectedDeviceId]);

  const activePreviewDevice =
    devices.find((d) => d.id === (hoveredDeviceId ?? selectedDeviceId)) ?? devices[0];

  const handlePresetClick = (preset: CameraPreset) => {
    setCameraPreset(preset);
    presetTriggerRef.current?.(preset);
  };

  const handleToggleAutoRotate = () => {
    setAutoRotate((prev) => {
      const next = !prev;
      autoRotateRef.current = next;
      if (next) {
        presetTriggerRef.current?.(cameraPreset);
      }
      return next;
    });
  };

  return (
    <div
      data-testid="topology-3d-container"
      className="relative w-full h-[360px] sm:h-auto sm:aspect-[16/10] bg-[#0B1120] border border-slate-800/90 rounded-lg overflow-hidden"
    >
      {/* Dedicated isolated WebGL canvas container */}
      <div ref={mountRef} className="absolute inset-0 w-full h-full" />

      {webglError && (
        <div className="absolute inset-0 flex flex-col items-center justify-center bg-[#0B1120] p-6 text-center">
          <p className="text-sm font-medium text-slate-200">Rendu 3D WebGL indisponible</p>
          <p className="text-xs text-slate-400 mt-1">
            Basculez vers la Vue 2D ci-dessus pour inspecter la topologie réseau.
          </p>
        </div>
      )}

      {/* Semantic HUD Overlay: Top-left inspected device telemetry (solid rgba, no backdrop-filter) */}
      {activePreviewDevice && !webglError && (
        <div className="pointer-events-none absolute top-3 left-3 z-10 bg-[#0F172A]/90 border border-slate-700/80 rounded-lg px-3 py-2 max-w-[260px]">
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono text-[11px] text-cyan-300">{activePreviewDevice.ip}</span>
            <SeverityBadge severity={getDeviceHighestSeverity(activePreviewDevice, findings)} />
          </div>
          <p className="mt-1 text-xs font-medium text-slate-100 truncate">
            {activePreviewDevice.hostname}
          </p>
          <p className="text-[11px] text-slate-400 tabular-nums">
            {activePreviewDevice.ports.filter((p) => p.state === 'open').length} port(s) ouvert(s)
          </p>
        </div>
      )}

      {/* Compact Bottom Camera Dock (no backdrop-filter over WebGL) */}
      {!webglError && (
        <div className="absolute bottom-3 left-1/2 -translate-x-1/2 z-10 flex items-center gap-1 p-1 rounded-lg bg-[#0F172A]/92 border border-slate-700/80">
          <button
            type="button"
            onClick={() => handlePresetClick('overview')}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[11px] font-medium transition-colors whitespace-nowrap ${
              cameraPreset === 'overview'
                ? 'bg-cyan-500/20 text-cyan-300'
                : 'text-slate-300 hover:text-white'
            }`}
          >
            <Maximize2 className="w-3 h-3" aria-hidden="true" />
            <span>Vue 3D globale</span>
          </button>

          <button
            type="button"
            onClick={() => handlePresetClick('focus')}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[11px] font-medium transition-colors whitespace-nowrap ${
              cameraPreset === 'focus'
                ? 'bg-cyan-500/20 text-cyan-300'
                : 'text-slate-300 hover:text-white'
            }`}
          >
            <Crosshair className="w-3 h-3" aria-hidden="true" />
            <span>Focus appareil</span>
          </button>

          <button
            type="button"
            onClick={() => handlePresetClick('zenith')}
            className={`px-2.5 py-1.5 rounded-md text-[11px] font-medium transition-colors whitespace-nowrap ${
              cameraPreset === 'zenith'
                ? 'bg-cyan-500/20 text-cyan-300'
                : 'text-slate-300 hover:text-white'
            }`}
          >
            Zénith
          </button>

          <button
            type="button"
            onClick={handleToggleAutoRotate}
            aria-pressed={autoRotate}
            className={`inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md text-[11px] font-medium transition-colors whitespace-nowrap ${
              autoRotate ? 'bg-emerald-500/20 text-emerald-300' : 'text-slate-300 hover:text-white'
            }`}
          >
            <RotateCw className="w-3 h-3" aria-hidden="true" />
            <span>Orbite</span>
          </button>
        </div>
      )}
    </div>
  );
}
