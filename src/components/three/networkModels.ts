import * as THREE from 'three';
import type { NetworkDevice, Severity } from '../../types/network';

export const RISK_HEX: Record<Severity | 'safe', number> = {
  critical: 0xef4444,
  high: 0xf59e0b,
  medium: 0x06b6d4,
  low: 0x64748b,
  safe: 0x10b981,
};

export function createRadarFloorTexture(maxAnisotropy: number): THREE.CanvasTexture {
  const size = 1024;
  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext('2d')!;

  ctx.fillStyle = '#090f1d';
  ctx.fillRect(0, 0, size, size);

  const cx = size / 2;
  const cy = size / 2;

  // Fine grid lines
  ctx.strokeStyle = 'rgba(34, 211, 238, 0.08)';
  ctx.lineWidth = 1;
  const step = size / 16;
  for (let i = 0; i <= 16; i += 1) {
    const p = i * step;
    ctx.beginPath();
    ctx.moveTo(p, 0);
    ctx.lineTo(p, size);
    ctx.stroke();

    ctx.beginPath();
    ctx.moveTo(0, p);
    ctx.lineTo(size, p);
    ctx.stroke();
  }

  // Concentric radar subnet rings
  const rings = [0.16, 0.28, 0.4, 0.48];
  rings.forEach((ratio, idx) => {
    ctx.beginPath();
    ctx.arc(cx, cy, size * ratio, 0, Math.PI * 2);
    ctx.strokeStyle = idx === 2 ? 'rgba(6, 182, 212, 0.26)' : 'rgba(56, 189, 248, 0.14)';
    ctx.lineWidth = idx === 2 ? 2 : 1.5;
    ctx.stroke();
  });

  // Diagonal crosshairs
  ctx.strokeStyle = 'rgba(6, 182, 212, 0.11)';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(0, cy);
  ctx.lineTo(size, cy);
  ctx.moveTo(cx, 0);
  ctx.lineTo(cx, size);
  ctx.stroke();

  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  texture.anisotropy = maxAnisotropy;
  texture.needsUpdate = true;
  return texture;
}

export function createContactShadowTexture(): THREE.CanvasTexture {
  const size = 128;
  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext('2d')!;

  const grad = ctx.createRadialGradient(size / 2, size / 2, 4, size / 2, size / 2, size / 2);
  grad.addColorStop(0, 'rgba(0, 0, 0, 0.62)');
  grad.addColorStop(0.55, 'rgba(0, 0, 0, 0.22)');
  grad.addColorStop(1, 'rgba(0, 0, 0, 0)');

  ctx.fillStyle = grad;
  ctx.fillRect(0, 0, size, size);

  const tex = new THREE.CanvasTexture(canvas);
  tex.colorSpace = THREE.SRGBColorSpace;
  tex.needsUpdate = true;
  return tex;
}

export interface SharedNodeAssets {
  chassisMat: THREE.MeshStandardMaterial;
  trimMat: THREE.MeshStandardMaterial;
  screenMat: THREE.MeshStandardMaterial;
  shadowMat: THREE.MeshBasicMaterial;
  hitboxMat: THREE.MeshBasicMaterial;
  shadowGeo: THREE.CircleGeometry;
}

export function createSharedNodeAssets(shadowTex: THREE.CanvasTexture): SharedNodeAssets {
  return {
    chassisMat: new THREE.MeshStandardMaterial({
      color: 0x1e293b,
      roughness: 0.72,
      metalness: 0.25,
    }),
    trimMat: new THREE.MeshStandardMaterial({
      color: 0x94a3b8,
      roughness: 0.24,
      metalness: 0.85,
    }),
    screenMat: new THREE.MeshStandardMaterial({
      color: 0x0f172a,
      roughness: 0.14,
      metalness: 0.15,
    }),
    shadowMat: new THREE.MeshBasicMaterial({
      map: shadowTex,
      transparent: true,
      depthWrite: false,
      opacity: 0.55,
    }),
    hitboxMat: new THREE.MeshBasicMaterial({
      visible: false,
    }),
    shadowGeo: new THREE.CircleGeometry(1.15, 24),
  };
}

export function buildHardwareNodeGroup(
  device: NetworkDevice,
  risk: Severity | 'safe',
  assets: SharedNodeAssets,
  isSoftwareGl: boolean
): { group: THREE.Group; hitbox: THREE.Mesh; ringMaterial: THREE.MeshStandardMaterial } {
  const group = new THREE.Group();
  group.userData = { deviceId: device.id };

  const riskColor = RISK_HEX[risk];
  const ringMaterial = new THREE.MeshStandardMaterial({
    color: riskColor,
    emissive: riskColor,
    emissiveIntensity: risk === 'critical' ? 1.35 : 0.85,
    roughness: 0.25,
    metalness: 0.35,
  });

  // Grounded contact shadow disc (y = 0.015 prevents Z-fighting with floor y = 0)
  const shadow = new THREE.Mesh(assets.shadowGeo, assets.shadowMat);
  shadow.rotation.x = -Math.PI / 2;
  shadow.position.y = 0.015;
  group.add(shadow);

  const cast = !isSoftwareGl;

  if (device.deviceType === 'gateway' || device.deviceType === 'firewall') {
    // 1. Hexagonal plinth base
    const base = new THREE.Mesh(new THREE.CylinderGeometry(0.95, 1.05, 0.18, 6), assets.trimMat);
    base.position.y = 0.09;
    base.castShadow = cast;
    base.receiveShadow = true;
    group.add(base);

    // 2. Armored hexagonal core chassis
    const body = new THREE.Mesh(new THREE.CylinderGeometry(0.8, 0.88, 0.72, 6), assets.chassisMat);
    body.position.y = 0.54;
    body.castShadow = cast;
    body.receiveShadow = true;
    group.add(body);

    // 3. Top shield cap
    const cap = new THREE.Mesh(new THREE.CylinderGeometry(0.58, 0.76, 0.2, 6), assets.trimMat);
    cap.position.y = 1.0;
    cap.castShadow = cast;
    group.add(cap);

    // 4. Dual telemetry antennae
    const antGeo = new THREE.CylinderGeometry(0.035, 0.045, 0.65, 8);
    const antLeft = new THREE.Mesh(antGeo, assets.trimMat);
    antLeft.position.set(-0.36, 1.32, -0.2);
    const antRight = new THREE.Mesh(antGeo, assets.trimMat);
    antRight.position.set(0.36, 1.32, -0.2);
    group.add(antLeft, antRight);

    // 5. Status halo ring
    const ring = new THREE.Mesh(new THREE.TorusGeometry(0.84, 0.045, 10, 24), ringMaterial);
    ring.rotation.x = Math.PI / 2;
    ring.position.y = 0.72;
    group.add(ring);
  } else if (device.deviceType === 'server' || device.deviceType === 'database') {
    // 1. Base plinth
    const plinth = new THREE.Mesh(new THREE.BoxGeometry(1.15, 0.12, 1.15), assets.trimMat);
    plinth.position.y = 0.06;
    plinth.castShadow = cast;
    plinth.receiveShadow = true;
    group.add(plinth);

    // 2. Main rack cabinet
    const height = device.deviceType === 'database' ? 1.55 : 1.35;
    const rack = new THREE.Mesh(new THREE.BoxGeometry(0.96, height, 0.96), assets.chassisMat);
    rack.position.y = 0.12 + height / 2;
    rack.castShadow = cast;
    rack.receiveShadow = true;
    group.add(rack);

    // 3. Front recessed bezel
    const bezel = new THREE.Mesh(new THREE.BoxGeometry(0.76, height - 0.24, 0.06), assets.screenMat);
    bezel.position.set(0, 0.12 + height / 2, 0.47);
    group.add(bezel);

    // 4. Illuminated blade slots (3 horizontal LEDs)
    const slotGeo = new THREE.BoxGeometry(0.56, 0.06, 0.03);
    for (let i = 0; i < 3; i += 1) {
      const slot = new THREE.Mesh(slotGeo, ringMaterial);
      slot.position.set(0, 0.45 + i * 0.34, 0.505);
      group.add(slot);
    }

    // 5. Top metallic crown
    const crown = new THREE.Mesh(new THREE.BoxGeometry(1.04, 0.1, 1.04), assets.trimMat);
    crown.position.y = 0.12 + height + 0.05;
    crown.castShadow = cast;
    group.add(crown);
  } else {
    // Workstation / Printer / IoT
    // 1. Pedestal base
    const stand = new THREE.Mesh(new THREE.CylinderGeometry(0.58, 0.68, 0.12, 16), assets.trimMat);
    stand.position.y = 0.06;
    stand.castShadow = cast;
    stand.receiveShadow = true;
    group.add(stand);

    // 2. Neck column
    const neck = new THREE.Mesh(new THREE.CylinderGeometry(0.14, 0.18, 0.42, 12), assets.trimMat);
    neck.position.y = 0.33;
    group.add(neck);

    // 3. Main body housing
    const body = new THREE.Mesh(new THREE.BoxGeometry(1.05, 0.68, 0.24), assets.chassisMat);
    body.position.set(0, 0.8, 0);
    body.castShadow = cast;
    group.add(body);

    // 4. Glossy display / optic visor
    const visor = new THREE.Mesh(new THREE.BoxGeometry(0.9, 0.54, 0.04), assets.screenMat);
    visor.position.set(0, 0.8, 0.13);
    group.add(visor);

    // 5. Base status beacon ring
    const ring = new THREE.Mesh(new THREE.TorusGeometry(0.62, 0.035, 10, 24), ringMaterial);
    ring.rotation.x = Math.PI / 2;
    ring.position.y = 0.14;
    group.add(ring);
  }

  // Dedicated invisible proxy hitbox for fast raycasting on layer 1
  const hitbox = new THREE.Mesh(new THREE.BoxGeometry(1.5, 1.9, 1.5), assets.hitboxMat);
  hitbox.position.y = 0.95;
  hitbox.userData = { deviceId: device.id };
  hitbox.layers.enable(1);
  group.add(hitbox);

  return { group, hitbox, ringMaterial };
}

export function buildLinkConduit(
  start: THREE.Vector3,
  end: THREE.Vector3,
  risk: Severity | 'safe'
): THREE.Mesh {
  const mid = new THREE.Vector3().addVectors(start, end).multiplyScalar(0.5);
  mid.y += 0.65;

  const curve = new THREE.QuadraticBezierCurve3(
    new THREE.Vector3(start.x, 0.25, start.z),
    mid,
    new THREE.Vector3(end.x, 0.25, end.z)
  );
  const geo = new THREE.TubeGeometry(curve, 20, 0.03, 6, false);
  const color = risk === 'critical' ? 0xef4444 : risk === 'high' ? 0xf59e0b : 0x06b6d4;
  const mat = new THREE.MeshStandardMaterial({
    color,
    emissive: color,
    emissiveIntensity: risk === 'critical' ? 0.7 : 0.4,
    roughness: 0.3,
    metalness: 0.2,
    transparent: true,
    opacity: 0.85,
  });

  return new THREE.Mesh(geo, mat);
}
