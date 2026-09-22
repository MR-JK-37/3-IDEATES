/**
 * Sandbox Viewer Screen
 * Isolated threat analysis with behavior playback
 */

import React from 'react';
import {View, Text, StyleSheet, ScrollView} from 'react-native';
import {COLORS, SPACING, TYPOGRAPHY} from '../../utils/constants';

const SandboxViewerScreen: React.FC = () => {
  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <View style={styles.header}>
        <Text style={styles.title}>Sandbox Analysis</Text>
        <Text style={styles.subtitle}>Isolated threat behavior analysis</Text>
      </View>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>🔬 Analysis Results</Text>
        <Text style={styles.emptyText}>
          Sandbox analysis will be implemented with isolated execution environment
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
  emptyText: {
    fontSize: TYPOGRAPHY.FONT_SIZE.MD,
    color: COLORS.TEXT_SECONDARY,
    textAlign: 'center',
    padding: SPACING.MD,
  },
});

export default SandboxViewerScreen;
