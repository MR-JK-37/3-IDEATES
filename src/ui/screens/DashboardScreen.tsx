/**
 * Dashboard Screen
 * Main overview of system health and active threats
 */

import React, {useEffect} from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Dimensions,
} from 'react-native';
import {useSelector, useDispatch} from 'react-redux';
import {RootState} from '../../store';
import {COLORS, SPACING, TYPOGRAPHY} from '../../utils/constants';
import {SystemHealth, ProtectionStatus} from '../../types';
import {setProtectionStatus} from '../../store/slices/systemHealthSlice';

const {width} = Dimensions.get('window');

const DashboardScreen: React.FC = () => {
  const dispatch = useDispatch();
  const systemHealth = useSelector((state: RootState) => state.systemHealth);
  const threats = useSelector((state: RootState) => state.threats);
  const settings = useSelector((state: RootState) => state.settings);

  useEffect(() => {
    // Initialize protection status
    if (systemHealth.protectionStatus === ProtectionStatus.INACTIVE) {
      dispatch(setProtectionStatus(ProtectionStatus.ACTIVE));
    }
  }, [dispatch, systemHealth.protectionStatus]);

  const getStatusColor = (status: ProtectionStatus): string => {
    switch (status) {
      case ProtectionStatus.ACTIVE:
        return COLORS.SUCCESS;
      case ProtectionStatus.SCANNING:
        return COLORS.WARNING;
      case ProtectionStatus.ERROR:
        return COLORS.ERROR;
      default:
        return COLORS.TEXT_SECONDARY;
    }
  };

  const getStatusIcon = (status: ProtectionStatus): string => {
    switch (status) {
      case ProtectionStatus.ACTIVE:
        return '✅';
      case ProtectionStatus.SCANNING:
        return '⏳';
      case ProtectionStatus.ERROR:
        return '❌';
      default:
        return '⚪';
    }
  };

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.title}>CyberDefense</Text>
        <View style={styles.statusContainer}>
          <Text style={styles.statusIcon}>
            {getStatusIcon(systemHealth.protectionStatus)}
          </Text>
          <Text
            style={[
              styles.statusText,
              {color: getStatusColor(systemHealth.protectionStatus)},
            ]}>
            {systemHealth.protectionStatus}
          </Text>
        </View>
      </View>

      {/* Protection Status Card */}
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Protection Status</Text>
        <View style={styles.statsRow}>
          <View style={styles.statItem}>
            <Text style={styles.statValue}>{systemHealth.activeThreats}</Text>
            <Text style={styles.statLabel}>Active Threats</Text>
          </View>
          <View style={styles.statItem}>
            <Text style={styles.statValue}>
              {systemHealth.threatsBlockedToday}
            </Text>
            <Text style={styles.statLabel}>Blocked Today</Text>
          </View>
          <View style={styles.statItem}>
            <Text style={styles.statValue}>
              {Math.round(systemHealth.batteryImpact * 10) / 10}%
            </Text>
            <Text style={styles.statLabel}>Battery Impact</Text>
          </View>
        </View>
      </View>

      {/* Engine Status Card */}
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Security Engines</Text>
        <View style={styles.engineList}>
          <EngineStatusItem
            name="Process Monitor"
            active={systemHealth.engineStatus.processMonitor}
          />
          <EngineStatusItem
            name="File Monitor"
            active={systemHealth.engineStatus.fileMonitor}
          />
          <EngineStatusItem
            name="Network Monitor"
            active={systemHealth.engineStatus.networkMonitor}
          />
          <EngineStatusItem
            name="Phishing Detector"
            active={systemHealth.engineStatus.phishingDetector}
          />
          <EngineStatusItem
            name="Malware Sandbox"
            active={systemHealth.engineStatus.malwareSandbox}
          />
        </View>
      </View>

      {/* Resource Usage Card */}
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Resource Usage</Text>
        <View style={styles.resourceRow}>
          <View style={styles.resourceItem}>
            <Text style={styles.resourceLabel}>CPU</Text>
            <Text style={styles.resourceValue}>
              {Math.round(systemHealth.cpuUsage)}%
            </Text>
          </View>
          <View style={styles.resourceItem}>
            <Text style={styles.resourceLabel}>Memory</Text>
            <Text style={styles.resourceValue}>
              {Math.round(systemHealth.memoryUsage)} MB
            </Text>
          </View>
        </View>
      </View>

      {/* Active Threats Card */}
      {threats.activeThreats.length > 0 && (
        <View style={[styles.card, styles.threatCard]}>
          <Text style={styles.cardTitle}>⚠️ Active Threats</Text>
          {threats.activeThreats.slice(0, 3).map(threat => (
            <View key={threat.id} style={styles.threatItem}>
              <Text style={styles.threatTitle}>{threat.title}</Text>
              <Text style={styles.threatDescription}>
                {threat.userFriendlyExplanation}
              </Text>
            </View>
          ))}
        </View>
      )}

      {/* Quick Actions */}
      <View style={styles.quickActions}>
        <TouchableOpacity style={styles.actionButton}>
          <Text style={styles.actionIcon}>🔍</Text>
          <Text style={styles.actionText}>Quick Scan</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.actionButton}>
          <Text style={styles.actionIcon}>📊</Text>
          <Text style={styles.actionText}>View Report</Text>
        </TouchableOpacity>
      </View>
    </ScrollView>
  );
};

const EngineStatusItem: React.FC<{name: string; active: boolean}> = ({
  name,
  active,
}) => (
  <View style={styles.engineItem}>
    <Text style={styles.engineIcon}>{active ? '✅' : '⚪'}</Text>
    <Text style={styles.engineName}>{name}</Text>
  </View>
);

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: COLORS.BACKGROUND,
  },
  content: {
    padding: SPACING.MD,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: SPACING.LG,
  },
  title: {
    fontSize: TYPOGRAPHY.FONT_SIZE.XXL,
    fontWeight: TYPOGRAPHY.FONT_WEIGHT.BOLD,
    color: COLORS.TEXT_PRIMARY,
  },
  statusContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: SPACING.SM,
  },
  statusIcon: {
    fontSize: 20,
  },
  statusText: {
    fontSize: TYPOGRAPHY.FONT_SIZE.MD,
    fontWeight: TYPOGRAPHY.FONT_WEIGHT.SEMI_BOLD,
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
  statsRow: {
    flexDirection: 'row',
    justifyContent: 'space-around',
  },
  statItem: {
    alignItems: 'center',
  },
  statValue: {
    fontSize: TYPOGRAPHY.FONT_SIZE.XL,
    fontWeight: TYPOGRAPHY.FONT_WEIGHT.BOLD,
    color: COLORS.PRIMARY,
    marginBottom: SPACING.XS,
  },
  statLabel: {
    fontSize: TYPOGRAPHY.FONT_SIZE.SM,
    color: COLORS.TEXT_SECONDARY,
  },
  engineList: {
    gap: SPACING.SM,
  },
  engineItem: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: SPACING.SM,
  },
  engineIcon: {
    fontSize: 16,
  },
  engineName: {
    fontSize: TYPOGRAPHY.FONT_SIZE.MD,
    color: COLORS.TEXT_PRIMARY,
  },
  resourceRow: {
    flexDirection: 'row',
    justifyContent: 'space-around',
  },
  resourceItem: {
    alignItems: 'center',
  },
  resourceLabel: {
    fontSize: TYPOGRAPHY.FONT_SIZE.SM,
    color: COLORS.TEXT_SECONDARY,
    marginBottom: SPACING.XS,
  },
  resourceValue: {
    fontSize: TYPOGRAPHY.FONT_SIZE.LG,
    fontWeight: TYPOGRAPHY.FONT_WEIGHT.BOLD,
    color: COLORS.PRIMARY,
  },
  threatCard: {
    borderColor: COLORS.THREAT_CRITICAL,
    borderWidth: 2,
  },
  threatItem: {
    marginBottom: SPACING.MD,
    paddingBottom: SPACING.MD,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.GLASS_BORDER,
  },
  threatTitle: {
    fontSize: TYPOGRAPHY.FONT_SIZE.MD,
    fontWeight: TYPOGRAPHY.FONT_WEIGHT.BOLD,
    color: COLORS.TEXT_PRIMARY,
    marginBottom: SPACING.XS,
  },
  threatDescription: {
    fontSize: TYPOGRAPHY.FONT_SIZE.SM,
    color: COLORS.TEXT_SECONDARY,
  },
  quickActions: {
    flexDirection: 'row',
    gap: SPACING.MD,
    marginTop: SPACING.MD,
  },
  actionButton: {
    flex: 1,
    backgroundColor: COLORS.SURFACE_ELEVATED,
    borderRadius: 12,
    padding: SPACING.MD,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: COLORS.GLASS_BORDER,
  },
  actionIcon: {
    fontSize: 32,
    marginBottom: SPACING.XS,
  },
  actionText: {
    fontSize: TYPOGRAPHY.FONT_SIZE.SM,
    color: COLORS.TEXT_PRIMARY,
    fontWeight: TYPOGRAPHY.FONT_WEIGHT.MEDIUM,
  },
});

export default DashboardScreen;
