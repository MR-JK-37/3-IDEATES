/**
 * Settings Screen
 * Feature toggles, sensitivity levels, exclusions
 */

import React from 'react';
import {View, Text, StyleSheet, ScrollView, Switch, TouchableOpacity} from 'react-native';
import {useSelector, useDispatch} from 'react-redux';
import {RootState} from '../../store';
import {toggleFeature, setSensitivityLevel} from '../../store/slices/settingsSlice';
import {COLORS, SPACING, TYPOGRAPHY} from '../../utils/constants';

const SettingsScreen: React.FC = () => {
  const dispatch = useDispatch();
  const settings = useSelector((state: RootState) => state.settings);

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <View style={styles.header}>
        <Text style={styles.title}>Settings</Text>
      </View>

      {/* Security Features */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Security Features</Text>
        <SettingItem
          label="Process Monitoring"
          value={settings.processMonitoring}
          onToggle={() => dispatch(toggleFeature('processMonitoring'))}
        />
        <SettingItem
          label="File Monitoring"
          value={settings.fileMonitoring}
          onToggle={() => dispatch(toggleFeature('fileMonitoring'))}
        />
        <SettingItem
          label="Network Monitoring"
          value={settings.networkMonitoring}
          onToggle={() => dispatch(toggleFeature('networkMonitoring'))}
        />
        <SettingItem
          label="Phishing Detection"
          value={settings.phishingDetection}
          onToggle={() => dispatch(toggleFeature('phishingDetection'))}
        />
        <SettingItem
          label="Malware Sandbox"
          value={settings.malwareSandbox}
          onToggle={() => dispatch(toggleFeature('malwareSandbox'))}
        />
      </View>

      {/* Sensitivity Level */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Sensitivity Level</Text>
        <View style={styles.sensitivityButtons}>
          {(['LOW', 'MEDIUM', 'HIGH'] as const).map(level => (
            <TouchableOpacity
              key={level}
              style={[
                styles.sensitivityButton,
                settings.sensitivityLevel === level && styles.sensitivityButtonActive,
              ]}
              onPress={() => dispatch(setSensitivityLevel(level))}>
              <Text
                style={[
                  styles.sensitivityButtonText,
                  settings.sensitivityLevel === level && styles.sensitivityButtonTextActive,
                ]}>
                {level}
              </Text>
            </TouchableOpacity>
          ))}
        </View>
      </View>

      {/* Preferences */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Preferences</Text>
        <SettingItem
          label="Notifications"
          value={settings.notificationsEnabled}
          onToggle={() => dispatch(toggleFeature('notificationsEnabled'))}
        />
        <SettingItem
          label="Haptic Feedback"
          value={settings.hapticFeedback}
          onToggle={() => dispatch(toggleFeature('hapticFeedback'))}
        />
        <SettingItem
          label="Dark Mode"
          value={settings.darkMode}
          onToggle={() => dispatch(toggleFeature('darkMode'))}
        />
      </View>

      {/* About */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>About</Text>
        <Text style={styles.aboutText}>CyberDefense Mobile v1.0.0</Text>
        <Text style={styles.aboutSubtext}>
          100% on-device processing • Zero cloud uploads • Privacy-first
        </Text>
      </View>
    </ScrollView>
  );
};

const SettingItem: React.FC<{
  label: string;
  value: boolean;
  onToggle: () => void;
}> = ({label, value, onToggle}) => (
  <View style={styles.settingItem}>
    <Text style={styles.settingLabel}>{label}</Text>
    <Switch
      value={value}
      onValueChange={onToggle}
      trackColor={{false: COLORS.SURFACE_ELEVATED, true: COLORS.PRIMARY}}
      thumbColor={value ? COLORS.TEXT_PRIMARY : COLORS.TEXT_SECONDARY}
    />
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
    marginBottom: SPACING.LG,
  },
  title: {
    fontSize: TYPOGRAPHY.FONT_SIZE.XXL,
    fontWeight: TYPOGRAPHY.FONT_WEIGHT.BOLD,
    color: COLORS.TEXT_PRIMARY,
  },
  section: {
    marginBottom: SPACING.XL,
  },
  sectionTitle: {
    fontSize: TYPOGRAPHY.FONT_SIZE.LG,
    fontWeight: TYPOGRAPHY.FONT_WEIGHT.BOLD,
    color: COLORS.TEXT_PRIMARY,
    marginBottom: SPACING.MD,
  },
  settingItem: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: SPACING.MD,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.GLASS_BORDER,
  },
  settingLabel: {
    fontSize: TYPOGRAPHY.FONT_SIZE.MD,
    color: COLORS.TEXT_PRIMARY,
  },
  sensitivityButtons: {
    flexDirection: 'row',
    gap: SPACING.SM,
  },
  sensitivityButton: {
    flex: 1,
    padding: SPACING.MD,
    borderRadius: 12,
    backgroundColor: COLORS.SURFACE_ELEVATED,
    alignItems: 'center',
    borderWidth: 2,
    borderColor: 'transparent',
  },
  sensitivityButtonActive: {
    borderColor: COLORS.PRIMARY,
    backgroundColor: COLORS.PRIMARY + '20',
  },
  sensitivityButtonText: {
    fontSize: TYPOGRAPHY.FONT_SIZE.MD,
    fontWeight: TYPOGRAPHY.FONT_WEIGHT.SEMI_BOLD,
    color: COLORS.TEXT_SECONDARY,
  },
  sensitivityButtonTextActive: {
    color: COLORS.PRIMARY,
  },
  aboutText: {
    fontSize: TYPOGRAPHY.FONT_SIZE.MD,
    color: COLORS.TEXT_PRIMARY,
    marginBottom: SPACING.XS,
  },
  aboutSubtext: {
    fontSize: TYPOGRAPHY.FONT_SIZE.SM,
    color: COLORS.TEXT_SECONDARY,
  },
});

export default SettingsScreen;
