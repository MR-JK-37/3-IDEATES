/**
 * Threat History Screen
 * Timeline of detected and blocked threats
 */

import React from 'react';
import {View, Text, StyleSheet, ScrollView, FlatList} from 'react-native';
import {useSelector} from 'react-redux';
import {RootState} from '../../store';
import {COLORS, SPACING, TYPOGRAPHY} from '../../utils/constants';
import {formatRelativeTime, getThreatLevelColor, getThreatTypeIcon} from '../../utils/helpers';

const ThreatHistoryScreen: React.FC = () => {
  const threats = useSelector((state: RootState) => state.threats);

  const renderThreatItem = ({item}: {item: any}) => (
    <View style={styles.threatCard}>
      <View style={styles.threatHeader}>
        <Text style={styles.threatIcon}>{getThreatTypeIcon(item.type)}</Text>
        <View style={styles.threatInfo}>
          <Text style={styles.threatTitle}>{item.title}</Text>
          <Text style={styles.threatTime}>{formatRelativeTime(item.timestamp)}</Text>
        </View>
        <View
          style={[
            styles.threatLevelBadge,
            {backgroundColor: getThreatLevelColor(item.level) + '20'},
          ]}>
          <Text
            style={[styles.threatLevelText, {color: getThreatLevelColor(item.level)}]}>
            {item.level}
          </Text>
        </View>
      </View>
      <Text style={styles.threatDescription}>{item.userFriendlyExplanation}</Text>
      {item.blocked && (
        <View style={styles.blockedBadge}>
          <Text style={styles.blockedText}>✓ Blocked</Text>
        </View>
      )}
    </View>
  );

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>Threat History</Text>
        <Text style={styles.subtitle}>
          {threats.totalBlocked} threats blocked | {threats.items.length} total detected
        </Text>
      </View>
      <FlatList
        data={threats.history}
        renderItem={renderThreatItem}
        keyExtractor={item => item.id}
        contentContainerStyle={styles.listContent}
        ListEmptyComponent={
          <View style={styles.emptyContainer}>
            <Text style={styles.emptyText}>No threats detected yet</Text>
            <Text style={styles.emptySubtext}>
              Your device is protected and monitored 24/7
            </Text>
          </View>
        }
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: COLORS.BACKGROUND,
  },
  header: {
    padding: SPACING.MD,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.GLASS_BORDER,
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
  listContent: {
    padding: SPACING.MD,
  },
  threatCard: {
    backgroundColor: COLORS.SURFACE,
    borderRadius: 16,
    padding: SPACING.MD,
    marginBottom: SPACING.MD,
    borderWidth: 1,
    borderColor: COLORS.GLASS_BORDER,
  },
  threatHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: SPACING.SM,
  },
  threatIcon: {
    fontSize: 24,
    marginRight: SPACING.SM,
  },
  threatInfo: {
    flex: 1,
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
  threatLevelBadge: {
    paddingHorizontal: SPACING.SM,
    paddingVertical: SPACING.XS,
    borderRadius: 8,
  },
  threatLevelText: {
    fontSize: TYPOGRAPHY.FONT_SIZE.XS,
    fontWeight: TYPOGRAPHY.FONT_WEIGHT.BOLD,
  },
  threatDescription: {
    fontSize: TYPOGRAPHY.FONT_SIZE.SM,
    color: COLORS.TEXT_SECONDARY,
    marginBottom: SPACING.SM,
  },
  blockedBadge: {
    alignSelf: 'flex-start',
    backgroundColor: COLORS.SUCCESS + '20',
    paddingHorizontal: SPACING.SM,
    paddingVertical: SPACING.XS,
    borderRadius: 8,
  },
  blockedText: {
    fontSize: TYPOGRAPHY.FONT_SIZE.XS,
    color: COLORS.SUCCESS,
    fontWeight: TYPOGRAPHY.FONT_WEIGHT.BOLD,
  },
  emptyContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    paddingVertical: SPACING.XXL,
  },
  emptyText: {
    fontSize: TYPOGRAPHY.FONT_SIZE.LG,
    color: COLORS.TEXT_PRIMARY,
    marginBottom: SPACING.SM,
  },
  emptySubtext: {
    fontSize: TYPOGRAPHY.FONT_SIZE.SM,
    color: COLORS.TEXT_SECONDARY,
  },
});

export default ThreatHistoryScreen;
