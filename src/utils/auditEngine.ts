import type {
  AuditSourceType,
  AuditSummary,
  GlobalRiskLevel,
  NetworkAuditResult,
  NetworkDevice,
  PortEntry,
  SecurityFinding,
  Severity,
} from '../types/network';

function parseSemverTuple(versionStr?: string): number[] | null {
  if (!versionStr) return null;
  const match = versionStr.match(/(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!match) return null;
  return [
    Number.parseInt(match[1] ?? '0', 10),
    Number.parseInt(match[2] ?? '0', 10),
    Number.parseInt(match[3] ?? '0', 10),
  ];
}

export function isVersionLessThan(versionStr: string | undefined, target: [number, number, number]): boolean {
  const parsed = parseSemverTuple(versionStr);
  if (!parsed) return false;
  for (let i = 0; i < 3; i += 1) {
    if (parsed[i] < target[i]) return true;
    if (parsed[i] > target[i]) return false;
  }
  return false;
}

export function isVersionInRange(
  versionStr: string | undefined,
  minInclusive: [number, number, number],
  maxInclusive: [number, number, number]
): boolean {
  const parsed = parseSemverTuple(versionStr);
  if (!parsed) return false;
  const gteMin = !isVersionLessThan(versionStr, minInclusive);
  const lteMax =
    isVersionLessThan(versionStr, maxInclusive) ||
    (parsed[0] === maxInclusive[0] && parsed[1] === maxInclusive[1] && parsed[2] === maxInclusive[2]);
  return gteMin && lteMax;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

const SEVERITY_PENALTY: Record<Severity, number> = {
  critical: 18,
  high: 10,
  medium: 5,
  low: 2,
};

export function inspectPortSecurity(device: NetworkDevice, portEntry: PortEntry): SecurityFinding[] {
  if (portEntry.state !== 'open') {
    return [];
  }

  const findings: SecurityFinding[] = [];
  const productLower = (portEntry.product ?? '').toLowerCase();
  const serviceLower = portEntry.service.toLowerCase();
  const bannerLower = (portEntry.banner ?? '').toLowerCase();
  const notesLower = (portEntry.configNotes ?? '').toLowerCase();
  const detectedVersion = [portEntry.product, portEntry.version].filter(Boolean).join(' ').trim() || undefined;

  const pushFinding = (finding: Omit<SecurityFinding, 'id' | 'deviceId' | 'deviceIp' | 'deviceHostname' | 'port' | 'protocol' | 'service' | 'detectedVersion'> & { detectedVersion?: string }) => {
    findings.push({
      id: `${device.id}-${portEntry.port}-${portEntry.protocol}-${findings.length + 1}`,
      deviceId: device.id,
      deviceIp: device.ip,
      deviceHostname: device.hostname,
      port: portEntry.port,
      protocol: portEntry.protocol,
      service: portEntry.service,
      detectedVersion: finding.detectedVersion ?? detectedVersion,
      ...finding,
    });
  };

  // --- 1. Vulnerable Service Versions ---

  // OpenSSH vulnerabilities
  if (productLower.includes('openssh')) {
    if (isVersionLessThan(portEntry.version, [8, 5, 0])) {
      pushFinding({
        category: 'vulnerable_version',
        severity: 'high',
        title: `OpenSSH obsolète (${portEntry.version ?? 'version ancienne'}) exposé`,
        cve: 'CVE-2023-38408 / CVE-2021-41617',
        cvss: 7.8,
        description: `Le service OpenSSH ${portEntry.version} présente plusieurs failles corrigées dans les branches récentes (transfert d'agent PKCS#11 et élévation de privilèges via AuthorizedKeysCommand).`,
        riskImpact: 'Risque de compromission à distance ou de mouvement latéral via le rebond SSH.',
        recommendation: 'Mettre à niveau OpenSSH vers la version 9.8p1 ou supérieure et désactiver les algorithmes obsolètes.',
        remediationSteps: [
          'Mettre à jour le paquet openssh-server via le gestionnaire de paquets du système.',
          'Forcer Protocol 2 et désactiver ssh-rsa / CBC dans /etc/ssh/sshd_config.',
          'Redémarrer le service sshd et vérifier la version active avec ssh -V.',
        ],
        priority: 'P1',
      });
    } else if (isVersionInRange(portEntry.version, [8, 5, 0], [9, 7, 9])) {
      pushFinding({
        category: 'vulnerable_version',
        severity: 'critical',
        title: `OpenSSH ${portEntry.version} potentiellement vulnérable (regreSSHion)`,
        cve: 'CVE-2024-6387',
        cvss: 8.1,
        description: `Les versions OpenSSH de 8.5p1 à 9.7p1 sur systèmes glibc sont exposées à une condition de course dans le gestionnaire de signaux sshd.`,
        riskImpact: 'Exécution de code non authentifiée possible à terme sur les serveurs exposés sans délai de grâce réduit.',
        recommendation: 'Mettre à jour vers OpenSSH >= 9.8p1 ou appliquer le correctif de votre distribution.',
        remediationSteps: [
          'Appliquer immédiatement les mises à jour de sécurité openssh-server (>= 9.8p1).',
          'En attente de patch, définir LoginGraceTime 0 dans /etc/ssh/sshd_config (attention au DoS potentiel) et restreindre l’accès par IP.',
        ],
        priority: 'P1',
      });
    }
  }

  // Apache HTTP Server
  if (productLower.includes('apache') || bannerLower.includes('apache/')) {
    if (
      portEntry.version &&
      (portEntry.version.startsWith('2.4.49') || portEntry.version.startsWith('2.4.50'))
    ) {
      pushFinding({
        category: 'vulnerable_version',
        severity: 'critical',
        title: `Apache HTTP Server ${portEntry.version} sujet au Path Traversal / RCE`,
        cve: 'CVE-2021-41773 / CVE-2021-42013',
        cvss: 9.8,
        description: `Apache httpd ${portEntry.version} contient une faille critique de traversée de chemin permettant la lecture de fichiers arbitraires et l'exécution de code si mod_cgi est actif.`,
        riskImpact: 'Compromission complète du serveur web et accès aux fichiers système sensibles.',
        recommendation: 'Mettre à jour Apache HTTP Server vers la version 2.4.62 ou ultérieure.',
        remediationSteps: [
          'Mettre à niveau apache2 / httpd vers la dernière version maintenue.',
          'Vérifier que Require all denied est appliqué sur le répertoire racine <Directory />.',
          'Masquer la bannière avec ServerTokens Prod et ServerSignature Off.',
        ],
        priority: 'P1',
      });
    } else if (isVersionLessThan(portEntry.version, [2, 4, 58])) {
      pushFinding({
        category: 'vulnerable_version',
        severity: 'high',
        title: `Apache HTTP Server ${portEntry.version ?? 'obsolète'} vulnérable`,
        cve: 'CVE-2023-25690',
        cvss: 7.5,
        description: `Cette version d'Apache httpd est exposée à des vulnérabilités de HTTP Request Smuggling via mod_proxy et mod_rewrite.`,
        riskImpact: 'Contournement des contrôles d’accès du reverse-proxy et détournement de requêtes HTTP.',
        recommendation: 'Mettre à jour Apache HTTP Server vers >= 2.4.59.',
        remediationSteps: [
          'Planifier la mise à jour d’Apache vers >= 2.4.59.',
          'Auditer les règles RewriteRule et ProxyPass.',
        ],
        priority: 'P2',
      });
    }
  }

  // Nginx
  if (productLower.includes('nginx') && isVersionLessThan(portEntry.version, [1, 24, 0])) {
    pushFinding({
      category: 'vulnerable_version',
      severity: 'medium',
      title: `Nginx ${portEntry.version} obsolète (HTTP/2 Rapid Reset / DNS resolver)`,
      cve: 'CVE-2023-44487',
      cvss: 6.5,
      description: `Les versions antérieures à Nginx 1.24.x/1.25.3 sont affectées par des failles de déni de service HTTP/2 et des corrections TLS manquantes.`,
      riskImpact: 'Saturation des ressources CPU et indisponibilité des services web exposés.',
      recommendation: 'Mettre à jour Nginx vers la branche stable 1.26.x et limiter les flux HTTP/2 concurrents.',
      remediationSteps: [
        'Mettre à niveau nginx vers >= 1.26.0.',
        'Configurer server_tokens off; dans nginx.conf.',
      ],
      priority: 'P2',
    });
  }

  // vsftpd 2.3.4 / obsolete FTP
  if (productLower.includes('vsftpd') && portEntry.version?.includes('2.3.4')) {
    pushFinding({
      category: 'vulnerable_version',
      severity: 'critical',
      title: 'vsftpd 2.3.4 compromis (porte dérobée connue)',
      cve: 'CVE-2011-2523',
      cvss: 10.0,
      description: 'La version 2.3.4 de vsftpd est associée à une porte dérobée critique permettant un accès shell non authentifié.',
      riskImpact: 'Prise de contrôle immédiate et totale de l’hôte avec privilèges élevés.',
      recommendation: 'Désactiver immédiatement vsftpd, auditer l’intégrité du système et migrer vers SFTP.',
      remediationSteps: [
        'Arrêter et désactiver le service vsftpd immédiatement.',
        'Remplacer les transferts FTP par SFTP (via OpenSSH) ou FTPS strict.',
        'Vérifier l’absence de comptes ou processus non autorisés sur la machine.',
      ],
      priority: 'P1',
    });
  }

  // Samba
  if (productLower.includes('samba') && isVersionLessThan(portEntry.version, [4, 17, 0])) {
    pushFinding({
      category: 'vulnerable_version',
      severity: 'high',
      title: `Samba ${portEntry.version} vulnérable`,
      cve: 'CVE-2021-44142',
      cvss: 8.8,
      description: 'Les anciennes versions de Samba comportent des failles de corruption mémoire dans le module VFS fruit et SMB.',
      riskImpact: 'Exécution de code à distance ou accès non autorisé aux partages de fichiers.',
      recommendation: 'Mettre à jour Samba vers >= 4.19 et imposer SMB3 avec chiffrement.',
      remediationSteps: [
        'Mettre à niveau les paquets samba vers la dernière version stable.',
        'Ajouter client min protocol = SMB3 et server min protocol = SMB3 dans smb.conf.',
      ],
      priority: 'P1',
    });
  }

  // Redis
  if (productLower.includes('redis') && isVersionLessThan(portEntry.version, [7, 0, 0])) {
    pushFinding({
      category: 'vulnerable_version',
      severity: 'high',
      title: `Redis ${portEntry.version} obsolète`,
      cve: 'CVE-2022-24735',
      cvss: 7.8,
      description: 'Version ancienne de Redis comportant des vulnérabilités d’exécution Lua et de gestion mémoire.',
      riskImpact: 'Fuite de données en cache ou exécution de commandes arbitraires.',
      recommendation: 'Mettre à niveau Redis vers 7.2+ et isoler le port 6379 sur localhost ou un VLAN privé.',
      remediationSteps: [
        'Mettre à niveau Redis vers >= 7.2.',
        'Restreindre bind 127.0.0.1 dans /etc/redis/redis.conf.',
      ],
      priority: 'P2',
    });
  }

  // IoT Embedded Web Servers (Boa / GoAhead / lighttpd old)
  if (productLower.includes('boa') || productLower.includes('goahead')) {
    pushFinding({
      category: 'vulnerable_version',
      severity: 'critical',
      title: `Serveur web embarqué non maintenu (${portEntry.product})`,
      cve: 'CVE-2021-45382',
      cvss: 9.1,
      description: `Le serveur HTTP embarqué ${portEntry.product} n'est plus maintenu et présente de nombreuses vulnérabilités critiques dans les firmwares IoT.`,
      riskImpact: 'Pivot réseau possible depuis l’équipement IoT vers le réseau interne.',
      recommendation: 'Isoler cet équipement dans un VLAN IoT dédié sans accès au réseau bureautique et mettre à jour le firmware.',
      remediationSteps: [
        'Rechercher et appliquer la dernière mise à jour firmware du constructeur.',
        'Placer l’appareil dans un VLAN IoT cloisonné avec filtrage strict en sortie.',
      ],
      priority: 'P1',
    });
  }

  // --- 2. Misconfigurations ---

  // Telnet open
  if (portEntry.port === 23 || serviceLower === 'telnet') {
    pushFinding({
      category: 'misconfiguration',
      severity: 'critical',
      title: 'Service Telnet actif en clair (port 23)',
      cvss: 9.0,
      description: 'Telnet transmet l’ensemble des identifiants et commandes d’administration sans aucun chiffrement sur le réseau.',
      riskImpact: 'Interception passive des mots de passe administrateur et prise de contrôle de l’équipement.',
      recommendation: 'Désactiver Telnet et utiliser exclusivement SSH v2 avec authentification par clé.',
      remediationSteps: [
        'Désactiver le démon telnetd ou l’accès Telnet dans l’interface d’administration.',
        'Bloquer le port TCP 23 via le pare-feu réseau et hôte.',
        'Activer SSH v2 restreint aux IP d’administration.',
      ],
      priority: 'P1',
    });
  }

  // Cleartext FTP
  if ((portEntry.port === 21 || serviceLower === 'ftp') && !portEntry.tlsEnabled) {
    pushFinding({
      category: 'misconfiguration',
      severity: 'high',
      title: 'Service FTP non chiffré actif (port 21)',
      cvss: 7.4,
      description: 'Le protocole FTP standard envoie les identifiants et les fichiers transférés en texte clair.',
      riskImpact: 'Exposition des comptes de service et interception des données transférées sur le LAN.',
      recommendation: 'Migrer vers SFTP (SSH) ou imposer FTPS explicite avec TLS 1.2/1.3.',
      remediationSteps: [
        'Désactiver le port 21 ou activer ssl_enable=YES et force_local_logins_ssl=YES.',
        'Privilégier SFTP sur le port 22 pour les échanges automatisés.',
      ],
      priority: 'P2',
    });
  }

  // Unauthenticated Redis
  if ((portEntry.port === 6379 || serviceLower === 'redis') && portEntry.authRequired === false) {
    pushFinding({
      category: 'misconfiguration',
      severity: 'critical',
      title: 'Instance Redis exposée sans authentification',
      cvss: 9.4,
      description: 'Le serveur Redis écoute sur une interface réseau accessible sans mot de passe requirepass ni ACL.',
      riskImpact: 'Lecture/effacement des données en mémoire et écriture potentielle de clés SSH ou tâches cron.',
      recommendation: 'Activer l’authentification ACL/requirepass et restreindre l’écoute à 127.0.0.1.',
      remediationSteps: [
        'Définir un mot de passe robuste ou des ACL dédiées dans redis.conf.',
        'Configurer bind 127.0.0.1 et protected-mode yes.',
        'Bloquer le port 6379 depuis les autres sous-réseaux.',
      ],
      priority: 'P1',
    });
  }

  // Unauthenticated MongoDB
  if ((portEntry.port === 27017 || serviceLower === 'mongodb') && portEntry.authRequired === false) {
    pushFinding({
      category: 'misconfiguration',
      severity: 'critical',
      title: 'Base MongoDB accessible sans contrôle d’authentification',
      cvss: 9.3,
      description: 'MongoDB répond sur le réseau sans l’option security.authorization: enabled.',
      riskImpact: 'Exfiltration ou destruction immédiate de toutes les collections de données.',
      recommendation: 'Activer l’authentification SCRAM-SHA-256 et limiter le bindIp au strict nécessaire.',
      remediationSteps: [
        'Créer un compte administrateur et activer security.authorization: enabled dans mongod.conf.',
        'Restreindre net.bindIp à localhost ou à l’adresse privée du serveur applicatif.',
      ],
      priority: 'P1',
    });
  }

  // Exposed Docker API
  if (portEntry.port === 2375) {
    pushFinding({
      category: 'misconfiguration',
      severity: 'critical',
      title: 'API Docker exposée en clair sans TLS (port 2375)',
      cvss: 9.8,
      description: 'Le socket TCP Docker 2375 permet à quiconque joignant le port de créer des conteneurs privilégiés sur l’hôte.',
      riskImpact: 'Élévation de privilèges root immédiate sur le serveur hôte.',
      recommendation: 'Désactiver l’écoute TCP 2375 ou basculer vers le port 2376 avec authentification mutuelle mTLS.',
      remediationSteps: [
        'Supprimer -H tcp://0.0.0.0:2375 de la configuration du démon Docker.',
        'Utiliser le socket Unix local (/var/run/docker.sock) ou un contexte SSH.',
      ],
      priority: 'P1',
    });
  }

  // SNMP v1/v2c default community
  if (
    (portEntry.port === 161 || serviceLower === 'snmp') &&
    (notesLower.includes('public') || notesLower.includes('v1') || notesLower.includes('v2c'))
  ) {
    pushFinding({
      category: 'misconfiguration',
      severity: 'medium',
      title: 'SNMP v1/v2c avec communauté par défaut détecté',
      cvss: 6.2,
      description: 'SNMP v1/v2c transmet les chaînes de communauté en clair; la communauté « public » expose la topologie et les métriques système.',
      riskImpact: 'Collecte d’informations système détaillées facilitant la cartographie par un attaquant.',
      recommendation: 'Migrer vers SNMPv3 avec authentification et chiffrement (authPriv) et restreindre les IP de supervision.',
      remediationSteps: [
        'Désactiver SNMP v1 et v2c sur l’équipement.',
        'Configurer un utilisateur SNMPv3 en mode authPriv (SHA-256 + AES).',
        'Limiter l’accès UDP/161 uniquement à l’adresse du serveur de supervision.',
      ],
      priority: 'P2',
    });
  }

  // SMB / NetBIOS exposure or SMBv1
  if (portEntry.port === 445 || portEntry.port === 139 || serviceLower.includes('smb') || serviceLower.includes('netbios')) {
    if (notesLower.includes('smbv1') || notesLower.includes('signing disabled') || notesLower.includes('guest')) {
      pushFinding({
        category: 'misconfiguration',
        severity: 'critical',
        title: 'Partage SMB mal configuré (SMBv1 / signature désactivée / accès invité)',
        cve: 'CVE-2017-0144 (risque protocolaire SMBv1)',
        cvss: 8.5,
        description: 'La prise en charge de SMBv1 ou l’absence de signature SMB expose les échanges réseau aux attaques par relais et aux rançongiciels.',
        riskImpact: 'Propagation latérale rapide sur le réseau interne et interception de sessions.',
        recommendation: 'Désactiver SMBv1, exiger la signature SMB et supprimer les accès anonymes/invités.',
        remediationSteps: [
          'Désactiver SMBv1 sur l’ensemble des postes et serveurs (Set-SmbServerConfiguration -EnableSMB1Protocol $false).',
          'Activer RequireSecuritySignature = 1 via GPO ou smb.conf.',
        ],
        priority: 'P1',
      });
    }
  }

  // HTTP without HTTPS on web/admin interface (unless explicitly 301 redirecting to HTTPS)
  if (
    (portEntry.port === 80 || portEntry.port === 8000 || portEntry.port === 8080 || portEntry.port === 8096 || serviceLower === 'http' || serviceLower === 'http-proxy') &&
    portEntry.tlsEnabled === false &&
    !bannerLower.includes('redirect 301 -> https')
  ) {
    const isAdmin = notesLower.includes('admin');
    pushFinding({
      category: 'misconfiguration',
      severity: isAdmin ? 'high' : 'medium',
      title: isAdmin
        ? 'Interface d’administration HTTP sans chiffrement TLS'
        : `Transfert HTTP non chiffré actif (port ${portEntry.port}) — migrer vers HTTPS`,
      cvss: isAdmin ? 7.2 : 5.8,
      description:
        'Le service web transmet ses échanges en HTTP en clair sans chiffrement TLS ni redirection automatique vers HTTPS.',
      riskImpact:
        'Interception ou altération des données, jetons de session et requêtes sur le réseau (absence d’intégrité et de confidentialité).',
      recommendation:
        'Activer HTTPS avec certificat valide (TLS 1.2/1.3), HSTS et redirection permanente 301 vers HTTPS.',
      remediationSteps: [
        'Déployer un certificat TLS interne ou ACME sur le serveur web.',
        'Configurer une redirection permanente 301 de HTTP vers HTTPS et activer l’en-tête Strict-Transport-Security (HSTS).',
      ],
      priority: isAdmin ? 'P2' : 'P3',
    });
  }

  // Weak TLS / TLS 1.0 / 1.1 or self-signed
  if (notesLower.includes('tls 1.0') || notesLower.includes('tls 1.1') || notesLower.includes('weak cipher')) {
    pushFinding({
      category: 'misconfiguration',
      severity: 'medium',
      title: 'Protocoles TLS obsolètes activés (TLS 1.0 / 1.1)',
      cvss: 5.9,
      description: 'Le service accepte encore des négociations TLS 1.0/1.1 ou des suites cryptographiques faibles.',
      riskImpact: 'Dégradation de la confidentialité des échanges et non-conformité réglementaire.',
      recommendation: 'Restreindre la configuration TLS exclusivement à TLSv1.2 et TLSv1.3.',
      remediationSteps: [
        'Mettre à jour la directive ssl_protocols / SSLProtocol vers TLSv1.2 TLSv1.3.',
        'Retirer les suites RC4, 3DES et RSA sans Forward Secrecy.',
      ],
      priority: 'P2',
    });
  }

  // Password / root SSH enabled
  if (portEntry.port === 22 && (notesLower.includes('passwordauth yes') || notesLower.includes('permitrootlogin yes'))) {
    pushFinding({
      category: 'misconfiguration',
      severity: 'high',
      title: 'Configuration SSH permissive (Root login / Mot de passe autorisé)',
      cvss: 7.1,
      description: 'Le serveur SSH autorise la connexion directe en root ou par simple mot de passe au lieu d’imposer des clés cryptographiques.',
      riskImpact: 'Vulnérabilité accrue aux attaques par dictionnaire ou pulvérisation de mots de passe.',
      recommendation: 'Désactiver PermitRootLogin et PasswordAuthentication dans sshd_config.',
      remediationSteps: [
        'Définir PermitRootLogin no et PasswordAuthentication no dans /etc/ssh/sshd_config.',
        'Utiliser exclusivement des clés Ed25519 et restreindre AllowUsers / AllowGroups.',
      ],
      priority: 'P2',
    });
  }

  // Exposed DB ports on network
  if (
    (portEntry.port === 3306 || portEntry.port === 5432 || portEntry.port === 1433) &&
    notesLower.includes('0.0.0.0')
  ) {
    pushFinding({
      category: 'misconfiguration',
      severity: 'medium',
      title: `Base de données (${portEntry.service}) liée à toutes les interfaces (0.0.0.0)`,
      cvss: 6.4,
      description: `Le moteur de base de données écoute sur l'ensemble des adresses réseau au lieu d'être limité aux serveurs applicatifs autorisés.`,
      riskImpact: 'Augmentation inutile de la surface d’attaque interne pour les comptes de base de données.',
      recommendation: 'Restreindre listen_addresses / bind-address et filtrer le port via pare-feu.',
      remediationSteps: [
        'Limiter l’écoute réseau aux adresses privées strictement nécessaires.',
        'Ajouter une règle pare-feu n’autorisant que l’IP du backend applicatif.',
      ],
      priority: 'P3',
    });
  }

  // RDP without NLA
  if (portEntry.port === 3389 && notesLower.includes('no nla')) {
    pushFinding({
      category: 'misconfiguration',
      severity: 'high',
      title: 'Bureau à distance RDP exposé sans NLA (Network Level Authentication)',
      cvss: 7.6,
      description: 'Le service RDP accepte des sessions graphiques avant authentification réseau préalable.',
      riskImpact: 'Surface d’attaque étendue aux failles pré-authentification RDP et épuisement de sessions.',
      recommendation: 'Activer NLA obligatoirement et placer RDP derrière un VPN ou une passerelle bastion.',
      remediationSteps: [
        'Activer « Autoriser uniquement les connexions avec authentification au niveau réseau (NLA) ».',
        'Restreindre le port TCP/UDP 3389 au sous-réseau d’administration ou VPN.',
      ],
      priority: 'P1',
    });
  }

  // VNC unencrypted
  if (portEntry.port === 5900 && !portEntry.tlsEnabled) {
    pushFinding({
      category: 'misconfiguration',
      severity: 'high',
      title: 'Service VNC exposé sans tunnel chiffré (port 5900)',
      cvss: 7.5,
      description: 'VNC utilise nativement un échange faiblement protégé et transmet le flux graphique sans TLS.',
      riskImpact: 'Observation du flux écran ou prise de contrôle graphique du poste à distance.',
      recommendation: 'Restreindre VNC à localhost et encapsuler les connexions dans un tunnel SSH ou VPN.',
      remediationSteps: [
        'Configurer VNC avec -localhost yes et bloquer le port 5900 sur le pare-feu.',
        'Utiliser un tunnel SSH (ssh -L 5900:127.0.0.1:5900) pour toute session distante.',
      ],
      priority: 'P2',
    });
  }

  // Unencrypted Print / JetDirect
  if (portEntry.port === 9100 && notesLower.includes('unauthenticated')) {
    pushFinding({
      category: 'misconfiguration',
      severity: 'low',
      title: 'Port d’impression directe JetDirect 9100 accessible sans restriction',
      cvss: 3.7,
      description: 'Le port 9100 permet d’envoyer des travaux PostScript/PJL directement à l’imprimante sans authentification.',
      riskImpact: 'Exposition potentielle de documents en file d’attente ou abus d’impression sur le réseau.',
      recommendation: 'Isoler les imprimantes dans un VLAN dédié et n’autoriser que le serveur d’impression sur le port 9100.',
      remediationSteps: [
        'Créer une ACL pare-feu autorisant uniquement le serveur d’impression vers TCP/9100.',
        'Désactiver les protocoles d’impression inutilisés (LPD, IPP non chiffré).',
      ],
      priority: 'P3',
    });
  }

  return findings;
}

export function computeHardeningScore(findings: SecurityFinding[]): number {
  if (findings.length === 0) return 100;
  const totalPenalty = findings.reduce((acc, f) => acc + SEVERITY_PENALTY[f.severity], 0);
  const raw = Math.round(100 * Math.exp(-totalPenalty / 95));
  return Math.max(5, Math.min(99, raw));
}

export function computeGlobalRiskLevel(summary: Omit<AuditSummary, 'globalRiskLevel'>): GlobalRiskLevel {
  if (summary.criticalCount > 0 || summary.hardeningScore < 45) return 'Critique';
  if (summary.highCount >= 2 || summary.hardeningScore < 70) return 'Élevé';
  if (summary.highCount === 1 || summary.mediumCount >= 2 || summary.hardeningScore < 85) return 'Modéré';
  return 'Faible';
}

export function evaluateNetworkAudit(params: {
  id: string;
  profileName: string;
  subnet: string;
  sourceType: AuditSourceType;
  devices: NetworkDevice[];
  durationMs?: number;
  scannedAt?: string;
}): NetworkAuditResult {
  const allFindings: SecurityFinding[] = [];
  let openPorts = 0;
  let closedPorts = 0;
  let filteredPorts = 0;

  for (const device of params.devices) {
    for (const port of device.ports) {
      if (port.state === 'open') openPorts += 1;
      else if (port.state === 'closed') closedPorts += 1;
      else if (port.state === 'filtered') filteredPorts += 1;

      const portFindings = inspectPortSecurity(device, port);
      allFindings.push(...portFindings);
    }
  }

  allFindings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const criticalCount = allFindings.filter((f) => f.severity === 'critical').length;
  const highCount = allFindings.filter((f) => f.severity === 'high').length;
  const mediumCount = allFindings.filter((f) => f.severity === 'medium').length;
  const lowCount = allFindings.filter((f) => f.severity === 'low').length;

  const hardeningScore = computeHardeningScore(allFindings);

  const partialSummary = {
    totalDevices: params.devices.length,
    openPorts,
    closedPorts,
    filteredPorts,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    hardeningScore,
  };

  return {
    id: params.id,
    profileName: params.profileName,
    subnet: params.subnet,
    sourceType: params.sourceType,
    scannedAt: params.scannedAt ?? new Date().toISOString(),
    durationMs: params.durationMs ?? 1840,
    devices: params.devices,
    findings: allFindings,
    summary: {
      ...partialSummary,
      globalRiskLevel: computeGlobalRiskLevel(partialSummary),
    },
  };
}

export function getDeviceHighestSeverity(device: NetworkDevice, findings: SecurityFinding[]): Severity | 'safe' {
  const deviceFindings = findings.filter((f) => f.deviceId === device.id);
  if (deviceFindings.length === 0) return 'safe';
  deviceFindings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  return deviceFindings[0].severity;
}
