/**
 * Network Monitor Screen
 * Traffic analysis and data leak detection
 */

import React from 'react';
import {View, Text, StyleSheet, ScrollView} from 'react-native';
import {COLORS, SPACING, TYPOGRAPHY} from '../../utils/constants';

const NetworkMonitorScreen: React.FC = () => {
  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <View style={styles.header}>
        <Text style={styles.title}>Network Monitor</Text>
        <Text style={styles.subtitle}>Traffic analysis and data leak detection</Text>
      </View>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>📊 Network Statistics</Text>
        <View style={styles.statsGrid}>
          <View style={styles.statBox}>
            <Text style={styles.statValue}>0</Text>
            <Text style={styles.statLabel}>Connections Blocked</Text>
          </View>
          <View style={styles.statBox}>
            <Text style={styles.statValue}>0 MB</Text>
            <Text style={styles.statLabel}>Data Monitored</Text>
          </View>
        </View>
      </View>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>🔒 Active Connections</Text>
        <Text style={styles.emptyText}>
          Network monitoring will be implemented with VpnService API
        </Text>
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
  statsGrid: {
    flexDirection: 'row',
    gap: SPACING.MD,
  },
  statBox: {
    flex: 1,
    backgroundColor: COLORS.SURFACE_ELEVATED,
    borderRadius: 12,
    padding: SPACING.MD,
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
    textAlign: 'center',
  },
  emptyText: {
    fontSize: TYPOGRAPHY.FONT_SIZE.MD,
    color: COLORS.TEXT_SECONDARY,
    textAlign: 'center',
    padding: SPACING.MD,
  },
});

export default NetworkMonitorScreen;
