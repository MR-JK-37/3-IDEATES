import React, { useEffect, useRef, useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Animated,
  Dimensions,
  Platform,
} from 'react-native';

const { width } = Dimensions.get('window');

// Dynamic imports to avoid runtime crash when libs aren't installed yet
let LinearGradient: any = null;
let BlurView: any = null;
try {
  // react-native-linear-gradient
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  LinearGradient = require('react-native-linear-gradient').default;
} catch (e) {
  LinearGradient = null;
}
try {
  // @react-native-community/blur
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const blurModule = require('@react-native-community/blur');
  BlurView = blurModule.BlurView || blurModule.default || null;
} catch (e) {
  BlurView = null;
}

export default function DashboardScreen(): JSX.Element {
  const [dashboard, setDashboard] = useState<any>({});
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const pulseAnim = useRef(new Animated.Value(1)).current;

  useEffect(() => {
    Animated.loop(
      Animated.sequence([
        Animated.timing(pulseAnim, { toValue: 1.18, duration: 900, useNativeDriver: true }),
        Animated.timing(pulseAnim, { toValue: 1, duration: 900, useNativeDriver: true }),
      ])
    ).start();
  }, [pulseAnim]);

  // Poll backend for live dashboard data
  useEffect(() => {
    let mounted = true;

    async function fetchDashboard() {
      try {
        const res = await fetch('http://localhost:5000/api/dashboard');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        if (!mounted) return;
        setDashboard(json);
        setError(null);
        setLoading(false);
      } catch (err: any) {
        if (!mounted) return;
        setError(err.message || 'Fetch error');
        setLoading(false);
      }
    }

    fetchDashboard();
    const id = setInterval(fetchDashboard, 3000);
    return () => {
      mounted = false;
      clearInterval(id);
    };
  }, []);

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <View style={styles.header}>
        <Text style={styles.logo}>🛡️ CYBERSHIELD PRO</Text>
        <Text style={styles.subtitle}>Real-Time Cyber Defense System</Text>
      </View>

      <GlassCard style={styles.statusCard}>
        <Text style={styles.cardTitle}>SYSTEM STATUS</Text>
        <View style={styles.statusRow}>
          <Text style={styles.statusLabel}>Monitoring:</Text>
          <View style={styles.statusValue}>
            <Animated.View style={[styles.statusDot, { transform: [{ scale: pulseAnim }] }]} />
              <Text style={styles.statusText}>{dashboard?.status || dashboard?.system?.status || (loading ? 'LOADING' : 'UNKNOWN')}</Text>
          </View>
        </View>

        <View style={styles.statusRow}>
          <Text style={styles.statusLabel}>Protected Since:</Text>
          <Text style={styles.statusText}>{dashboard?.protected_since || '—'}</Text>
        </View>

        <View style={styles.statusRow}>
          <Text style={styles.statusLabel}>Last Scan:</Text>
          <Text style={styles.statusText}>{dashboard?.last_scan || (new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }))}</Text>
        </View>

        <View style={styles.statusRow}>
          <Text style={styles.statusLabel}>OS Version:</Text>
          <Text style={styles.statusText}>{Platform.OS} {Platform.Version}</Text>
        </View>

        <View style={styles.resourceSection}>
          <ProgressBar label="CPU" value={Math.round((dashboard?.metrics?.cpu_percent ?? dashboard?.system?.cpu_percent) ?? 0)} color="#00f5ff" />
          <ProgressBar label="MEM" value={Math.round((dashboard?.metrics?.memory_percent ?? dashboard?.system?.memory_percent) ?? 0)} color="#8338ec" />
          <ProgressBar label="NET" value={Math.round((dashboard?.metrics?.network_percent ?? 0))} color="#06ffa5" />
        </View>
        {error ? <Text style={{ color: '#ff6b6b', marginTop: 8 }}>{error}</Text> : null}
      </GlassCard>

      <View style={styles.threatsGrid}>
        <ThreatCard count={dashboard?.security?.threats_recent ?? dashboard?.summary?.critical ?? 0} label="Critical" subtitle="Blocked Today" color="#ff006e" icon="🔴" />
        <ThreatCard count={dashboard?.security?.threats_total ?? dashboard?.summary?.high ?? 0} label="High Risk" subtitle="Quarantined" color="#ff8500" icon="🟠" />
        <ThreatCard count={dashboard?.security?.threats_total ?? dashboard?.summary?.total ?? 0} label="Total" subtitle="Threats Found" color="#06ffa5" icon="🟢" />
      </View>

      <GlassCard style={styles.liveCard}>
        <Text style={styles.cardTitle}>🎯 LIVE THREAT ACTIVITY</Text>
        <LiveNetworkGraph nodes={dashboard?.network?.connections ?? []} />
      </GlassCard>

      <GlassCard style={styles.threatsCard}>
        <Text style={styles.cardTitle}>⚡ RECENT THREATS</Text>
        {loading && <Text style={{ color: 'rgba(255,255,255,0.6)' }}>Loading threats…</Text>}
        {!loading && (dashboard?.threats?.length ?? 0) === 0 && <Text style={{ color: 'rgba(255,255,255,0.6)' }}>No active threats</Text>}
        {(dashboard?.threats ?? []).map((t: any, idx: number) => (
          <ThreatItem
            key={idx}
            type={t.type}
            severity={t.severity}
            name={t.display || t.name}
            description={t.description}
            time={t.time || t.detected_at}
            color={t.color || (t.severity === 'CRITICAL' ? '#ff006e' : t.severity === 'HIGH' ? '#ff8500' : '#ffbe0b')}
            details={t.details}
          />
        ))}
      </GlassCard>
    </ScrollView>
  );
}

function GlassCard({ children, style }: { children: React.ReactNode; style?: any }) {
  if (BlurView) {
    // @ts-ignore - BlurView typing may differ between installs
    return (
      // @ts-ignore
      <BlurView style={[styles.glassCard, style]} blurAmount={20} blurType="dark">
        {children}
      </BlurView>
    );
  }
  return <View style={[styles.glassCard, style]}>{children}</View>;
}

function ThreatCard({ count, label, subtitle, color, icon }: { count: number; label: string; subtitle: string; color: string; icon: string }) {
  const inner = (
    <View style={[styles.threatCardGradient, { backgroundColor: color + '12' }]}> 
      <Text style={styles.threatIcon}>{icon}</Text>
      <Text style={[styles.threatCount, { color }]}>{count}</Text>
      <Text style={styles.threatLabel}>{label}</Text>
      <Text style={styles.threatSubtitle}>{subtitle}</Text>
    </View>
  );

  return (
    <TouchableOpacity style={styles.threatCard} activeOpacity={0.85}>
      {LinearGradient ? (
        <LinearGradient colors={[color + '40', color + '10']} style={styles.threatCardGradient}>
          {inner}
        </LinearGradient>
      ) : (
        inner
      )}
    </TouchableOpacity>
  );
}

function ProgressBar({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <View style={styles.progressContainer}>
      <Text style={styles.progressLabel}>{label}:</Text>
      <View style={styles.progressBar}>
        <View style={[styles.progressFill, { width: `${value}%`, backgroundColor: color }]} />
      </View>
      <Text style={styles.progressValue}>{value}%</Text>
    </View>
  );
}

function ThreatItem({ type, severity, name, description, time, color, details }: any) {
  const yaraMatches = details?.yara_matches ?? [];
  return (
    <TouchableOpacity style={[styles.threatItem, { borderLeftColor: color }]} activeOpacity={0.9}>
      <View style={[styles.threatBadge, { backgroundColor: color + '20' }]}> 
        <Text style={[styles.threatType, { color }]}>{type}</Text>
      </View>
      <View style={styles.threatContent}>
        <View style={styles.threatHeader}>
          <Text style={styles.threatName}>{name}</Text>
          <Text style={[styles.threatSeverity, { color }]}>{severity}</Text>
        </View>
        <Text style={styles.threatDescription}>{description}</Text>
        {yaraMatches.length > 0 && (
          <View style={{ marginTop: 8 }}>
            <Text style={{ color: '#ffcc00', fontWeight: '800' }}>⚠ YARA Match detected</Text>
            {yaraMatches.map((r: string, i: number) => (
              <Text key={i} style={{ color: 'rgba(255,255,255,0.85)', fontSize: 12 }}>{r}</Text>
            ))}
          </View>
        )}
        <View style={styles.threatFooter}>
          <Text style={styles.threatTime}>{time}</Text>
          <View style={styles.threatActions}>
            <TouchableOpacity style={styles.actionButton}><Text style={styles.actionText}>Details</Text></TouchableOpacity>
            <TouchableOpacity style={[styles.actionButton, styles.actionDanger]}><Text style={styles.actionText}>Block</Text></TouchableOpacity>
          </View>
        </View>
      </View>
    </TouchableOpacity>
  );
}

// Animated Live Network Graph
function LiveNetworkGraph() {
  const pulse1 = useRef(new Animated.Value(0)).current;
  const pulse2 = useRef(new Animated.Value(0)).current;
  const pulse3 = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    const anim = (value: Animated.Value, delay: number) => {
      return Animated.loop(
        Animated.sequence([
          Animated.timing(value, { toValue: 1, duration: 700, useNativeDriver: true, delay }),
          Animated.timing(value, { toValue: 0, duration: 700, useNativeDriver: true }),
        ])
      );
    };
    const a1 = anim(pulse1, 0);
    const a2 = anim(pulse2, 300);
    const a3 = anim(pulse3, 600);
    a1.start();
    a2.start();
    a3.start();
    return () => {
      a1.stop();
      a2.stop();
      a3.stop();
    };
  }, [pulse1, pulse2, pulse3]);

  const Node = ({ label, color, pulse }: { label: string; color: string; pulse: Animated.Value }) => {
    const scale = pulse.interpolate({ inputRange: [0, 1], outputRange: [1, 1.6] });
    const opacity = pulse.interpolate({ inputRange: [0, 1], outputRange: [0.6, 0.12] });
    return (
      <View style={styles.nodeRow}>
        <View style={styles.nodeWrapper}>
          <Animated.View style={[styles.nodePulse, { backgroundColor: color, transform: [{ scale }], opacity }]} />
          <View style={[styles.nodeCore, { backgroundColor: color }]} />
        </View>
        <Text style={styles.nodeLabel}>{label}</Text>
      </View>
    );
  };

  return (
    <View style={styles.networkContainer}>
      <View style={styles.deviceColumn}>
        <View style={styles.deviceBubble}>
          <Text style={styles.deviceText}>📱</Text>
        </View>
        <Text style={styles.deviceLabel}>Device</Text>
      </View>

      <View style={styles.connectionsColumn}>
        <View style={styles.connectionRow}>
          <View style={styles.line} />
          <Node label="45.67.89.123 (Blocked C2)" color="#ff006e" pulse={pulse1} />
        </View>
        <View style={styles.connectionRow}>
          <View style={styles.line} />
          <Node label="cloudflare.com (Safe)" color="#06ffa5" pulse={pulse2} />
        </View>
        <View style={styles.connectionRow}>
          <View style={styles.line} />
          <Node label="suspicious-site.xyz (Analyzing)" color="#ff8500" pulse={pulse3} />
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#0a0e27' },
  content: { paddingBottom: 40 },
  header: { padding: 20, alignItems: 'center' },
  logo: { fontSize: 28, fontWeight: '800', color: '#00f5ff', textShadowColor: '#00f5ff', textShadowRadius: 8 },
  subtitle: { fontSize: 14, color: 'rgba(255,255,255,0.75)', marginTop: 6 },
  glassCard: {
    marginHorizontal: 16,
    marginVertical: 8,
    padding: 18,
    borderRadius: 16,
    backgroundColor: 'rgba(255,255,255,0.04)',
    borderWidth: 1,
    borderColor: 'rgba(0,245,255,0.12)',
    shadowColor: '#00f5ff',
    shadowOpacity: Platform.OS === 'ios' ? 0.08 : 0.03,
    shadowRadius: 20,
    elevation: 6,
  },
  cardTitle: { fontSize: 16, fontWeight: '700', color: '#00f5ff', marginBottom: 12, textTransform: 'uppercase', letterSpacing: 1 },
  statusRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginVertical: 6 },
  statusLabel: { fontSize: 13, color: 'rgba(255,255,255,0.75)' },
  statusValue: { flexDirection: 'row', alignItems: 'center' },
  statusDot: { width: 12, height: 12, borderRadius: 6, marginRight: 8, backgroundColor: '#06ffa5' },
  statusText: { fontSize: 14, color: '#fff', fontWeight: '600' },
  resourceSection: { marginTop: 14, paddingTop: 12, borderTopWidth: 1, borderTopColor: 'rgba(255,255,255,0.04)' },
  progressContainer: { flexDirection: 'row', alignItems: 'center', marginVertical: 6 },
  progressLabel: { fontSize: 12, color: 'rgba(255,255,255,0.75)', width: 40 },
  progressBar: { flex: 1, height: 8, backgroundColor: 'rgba(255,255,255,0.06)', borderRadius: 6, marginHorizontal: 12, overflow: 'hidden' },
  progressFill: { height: '100%', borderRadius: 6 },
  progressValue: { fontSize: 12, color: '#fff', width: 44, textAlign: 'right' },
  threatsGrid: { flexDirection: 'row', justifyContent: 'space-between', paddingHorizontal: 16, marginTop: 8 },
  threatCard: { flex: 1, marginHorizontal: 6, borderRadius: 12, overflow: 'hidden' },
  threatCardGradient: { padding: 14, alignItems: 'center' },
  threatIcon: { fontSize: 28, marginBottom: 6 },
  threatCount: { fontSize: 30, fontWeight: '900', marginVertical: 6 },
  threatLabel: { fontSize: 13, color: '#fff', fontWeight: '700' },
  threatSubtitle: { fontSize: 11, color: 'rgba(255,255,255,0.65)', marginTop: 6, textAlign: 'center' },
  liveCard: { minHeight: 180 },
  networkContainer: { flexDirection: 'row', alignItems: 'flex-start', paddingVertical: 8 },
  deviceColumn: { width: 80, alignItems: 'center' },
  deviceBubble: { width: 56, height: 56, borderRadius: 28, backgroundColor: 'rgba(255,255,255,0.04)', alignItems: 'center', justifyContent: 'center', marginBottom: 6, borderWidth: 1, borderColor: 'rgba(0,245,255,0.08)' },
  deviceText: { fontSize: 24 },
  deviceLabel: { fontSize: 12, color: 'rgba(255,255,255,0.7)' },
  connectionsColumn: { flex: 1, paddingLeft: 8 },
  connectionRow: { flexDirection: 'row', alignItems: 'center', marginVertical: 8 },
  line: { width: 12, height: 2, backgroundColor: 'rgba(255,255,255,0.06)', marginRight: 8, borderRadius: 2 },
  nodeRow: { flexDirection: 'row', alignItems: 'center' },
  nodeWrapper: { width: 28, height: 28, alignItems: 'center', justifyContent: 'center', marginRight: 10 },
  nodePulse: { position: 'absolute', width: 28, height: 28, borderRadius: 14 },
  nodeCore: { width: 10, height: 10, borderRadius: 5 },
  nodeLabel: { color: 'rgba(255,255,255,0.9)', fontSize: 13, flexShrink: 1 },
  threatItem: { backgroundColor: 'rgba(255,255,255,0.02)', borderRadius: 12, padding: 14, marginVertical: 8, borderLeftWidth: 4 },
  threatBadge: { alignSelf: 'flex-start', paddingHorizontal: 10, paddingVertical: 6, borderRadius: 8, marginBottom: 8 },
  threatType: { fontSize: 11, fontWeight: '800', textTransform: 'uppercase', letterSpacing: 1 },
  threatContent: {},
  threatHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 },
  threatName: { fontSize: 16, fontWeight: '800', color: '#fff' },
  threatSeverity: { fontSize: 12, fontWeight: '800' },
  threatDescription: { fontSize: 13, color: 'rgba(255,255,255,0.75)', lineHeight: 20, marginBottom: 10 },
  threatFooter: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  threatTime: { fontSize: 12, color: 'rgba(255,255,255,0.5)' },
  threatActions: { flexDirection: 'row' },
  actionButton: { paddingHorizontal: 10, paddingVertical: 6, borderRadius: 8, backgroundColor: 'rgba(0,245,255,0.08)', marginLeft: 8 },
  actionDanger: { backgroundColor: 'rgba(255,0,110,0.08)' },
  actionText: { fontSize: 12, color: '#fff', fontWeight: '700' },
});
