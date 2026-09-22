/**
 * Live Monitor Screen
 * Real-time threat visualization and attack replay
 */

import React from 'react';
import {View, Text, StyleSheet, ScrollView} from 'react-native';
import {useSelector} from 'react-redux';
import {RootState} from '../../store';
import {COLORS, SPACING, TYPOGRAPHY} from '../../utils/constants';

const LiveMonitorScreen: React.FC = () => {
  const threats = useSelector((state: RootState) => state.threats);
  const processes = useSelector((state: RootState) => state.processes);

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <View style={styles.header}>
        <Text style={styles.title}>Live Monitor</Text>
        <Text style={styles.subtitle}>Real-time threat visualization</Text>
      </View>

      {/* Network Graph Placeholder */}
      <View style={styles.card}>
        <Text style={styles.cardTitle}>🌐 Network Activity</Text>
        <View style={styles.placeholder}>
          <Text style={styles.placeholderText}>
            Network graph visualization will appear here
          </Text>
          <Text style={styles.placeholderSubtext}>
            Showing blocked and allowed traffic in real-time
          </Text>
        </View>
      </View>

      {/* Process Tree */}
      <View style={styles.card}>
        <Text style={styles.cardTitle}>⚙️ Process Tree</Text>
        {processes.suspiciousProcesses.length > 0 ? (
          processes.suspiciousProcesses.slice(0, 5).map(process => (
            <View key={process.pid} style={styles.processItem}>
              <View style={styles.processHeader}>
                <Text style={styles.processName}>{process.name}</Text>
                <Text style={styles.riskScore}>Risk: {process.riskScore}%</Text>
              </View>
              <Text style={styles.processDetails}>
                PID: {process.pid} | CPU: {process.cpuUsage.toFixed(1)}% | Memory:{' '}
                {process.memoryUsage.toFixed(1)} MB
              </Text>
              {process.isHidden && (
                <Text style={styles.hiddenLabel}>⚠️ Hidden Process</Text>
              )}
            </View>
          ))
        ) : (
          <Text style={styles.emptyText}>No suspicious processes detected</Text>
        )}
      </View>

      {/* Recent Threats */}
      <View style={styles.card}>
        <Text style={styles.cardTitle}>🔴 Recent Threats</Text>
        {threats.items.slice(0, 5).map(threat => (
          <View key={threat.id} style={styles.threatItem}>
            <Text style={styles.threatType}>{threat.type}</Text>
            <Text style={styles.threatTitle}>{threat.title}</Text>
            <Text style={styles.threatTime}>
              {new Date(threat.timestamp).toLocaleTimeString()}
            </Text>
          </View>
        ))}
      </View>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: COLORS.BACKGROUND,
  },
  content: {
    padding: SPACING.MD,
  },
  header: {
    marginBottom: SPACING.LG,
  },
  title: {
    fontSize: TYPOGRAPHY.FONT_SIZE.XXL,
    fontWeight: TYPOGRAPHY.FONT_WEIGHT.BOLD,
    color: COLORS.TEXT_PRIMARY,
    marginBottom: SPACING.XS,
  },
  subtitle: {
    fontSize: TYPOGRAPHY.FONT_SIZE.SM,
    color: COLORS.TEXT_SECONDARY,
  },
  card: {
    backgroundColor: COLORS.SURFACE,
    borderRadius: 16,
    padding: SPACING.MD,
    marginBottom: SPACING.MD,
    borderWidth: 1,
    borderColor: COLORS.GLASS_BORDER,
  },
  cardTitle: {
    fontSize: TYPOGRAPHY.FONT_SIZE.LG,
    fontWeight: TYPOGRAPHY.FONT_WEIGHT.BOLD,
    color: COLORS.TEXT_PRIMARY,
    marginBottom: SPACING.MD,
  },
  placeholder: {
    height: 200,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: COLORS.SURFACE_ELEVATED,
    borderRadius: 12,
  },
  placeholderText: {
    fontSize: TYPOGRAPHY.FONT_SIZE.MD,
    color: COLORS.TEXT_PRIMARY,
    marginBottom: SPACING.XS,
  },
  placeholderSubtext: {
    fontSize: TYPOGRAPHY.FONT_SIZE.SM,
    color: COLORS.TEXT_SECONDARY,
  },
  processItem: {
    padding: SPACING.SM,
    marginBottom: SPACING.SM,
    backgroundColor: COLORS.SURFACE_ELEVATED,
    borderRadius: 8,
  },
  processHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: SPACING.XS,
  },
  processName: {
    fontSize: TYPOGRAPHY.FONT_SIZE.MD,
    fontWeight: TYPOGRAPHY.FONT_WEIGHT.BOLD,
    color: COLORS.TEXT_PRIMARY,
  },
  riskScore: {
    fontSize: TYPOGRAPHY.FONT_SIZE.SM,
    color: COLORS.THREAT_HIGH,
    fontWeight: TYPOGRAPHY.FONT_WEIGHT.SEMI_BOLD,
  },
  processDetails: {
    fontSize: TYPOGRAPHY.FONT_SIZE.SM,
    color: COLORS.TEXT_SECONDARY,
  },
  hiddenLabel: {
    fontSize: TYPOGRAPHY.FONT_SIZE.XS,
    color: COLORS.WARNING,
    marginTop: SPACING.XS,
  },
  emptyText: {
    fontSize: TYPOGRAPHY.FONT_SIZE.MD,
    color: COLORS.TEXT_SECONDARY,
    textAlign: 'center',
    padding: SPACING.MD,
  },
  threatItem: {
    padding: SPACING.SM,
    marginBottom: SPACING.SM,
    backgroundColor: COLORS.SURFACE_ELEVATED,
    borderRadius: 8,
    borderLeftWidth: 3,
    borderLeftColor: COLORS.THREAT_CRITICAL,
  },
  threatType: {
    fontSize: TYPOGRAPHY.FONT_SIZE.XS,
    color: COLORS.TEXT_SECONDARY,
    marginBottom: SPACING.XS,
  },
  threatTitle: {
    fontSize: TYPOGRAPHY.FONT_SIZE.MD,
    fontWeight: TYPOGRAPHY.FONT_WEIGHT.BOLD,
    color: COLORS.TEXT_PRIMARY,
    marginBottom: SPACING.XS,
  },
  threatTime: {
    fontSize: TYPOGRAPHY.FONT_SIZE.XS,
    color: COLORS.TEXT_SECONDARY,
  },
});

export default LiveMonitorScreen;
