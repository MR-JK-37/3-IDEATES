/**
 * Main Application Component
 * CyberDefense Mobile - Real-Time Cyber Defense Application
 */

import React, {useEffect} from 'react';
import {StatusBar, Platform, Text} from 'react-native';
import {NavigationContainer} from '@react-navigation/native';
import {createStackNavigator} from '@react-navigation/stack';
import {createBottomTabNavigator} from '@react-navigation/bottom-tabs';
import {Provider} from 'react-redux';
import {store} from './src/store';
import {COLORS} from './src/utils/constants';
import EngineService from './src/services/EngineService';

// Screens
import DashboardScreen from './src/ui/screens/DashboardScreen';
import LiveMonitorScreen from './src/ui/screens/LiveMonitorScreen';
import SandboxViewerScreen from './src/ui/screens/SandboxViewerScreen';
import NetworkMonitorScreen from './src/ui/screens/NetworkMonitorScreen';
import ThreatHistoryScreen from './src/ui/screens/ThreatHistoryScreen';
import SettingsScreen from './src/ui/screens/SettingsScreen';

const Stack = createStackNavigator();
const Tab = createBottomTabNavigator();

/**
 * Main Tab Navigator
 */
function MainTabs() {
  return (
    <Tab.Navigator
      screenOptions={{
        headerShown: false,
        tabBarStyle: {
          backgroundColor: COLORS.SURFACE,
          borderTopColor: COLORS.GLASS_BORDER,
          borderTopWidth: 1,
          paddingBottom: Platform.OS === 'ios' ? 20 : 10,
          height: Platform.OS === 'ios' ? 90 : 70,
        },
        tabBarActiveTintColor: COLORS.PRIMARY,
        tabBarInactiveTintColor: COLORS.TEXT_SECONDARY,
        tabBarLabelStyle: {
          fontSize: 12,
          fontWeight: '600',
        },
      }}>
      <Tab.Screen
        name="Dashboard"
        component={DashboardScreen}
        options={{
          tabBarIcon: ({color}) => <TabIcon icon="🛡️" color={color} />,
        }}
      />
      <Tab.Screen
        name="LiveMonitor"
        component={LiveMonitorScreen}
        options={{
          tabBarLabel: 'Live Monitor',
          tabBarIcon: ({color}) => <TabIcon icon="📊" color={color} />,
        }}
      />
      <Tab.Screen
        name="Network"
        component={NetworkMonitorScreen}
        options={{
          tabBarIcon: ({color}) => <TabIcon icon="🌐" color={color} />,
        }}
      />
      <Tab.Screen
        name="History"
        component={ThreatHistoryScreen}
        options={{
          tabBarIcon: ({color}) => <TabIcon icon="📜" color={color} />,
        }}
      />
      <Tab.Screen
        name="Settings"
        component={SettingsScreen}
        options={{
          tabBarIcon: ({color}) => <TabIcon icon="⚙️" color={color} />,
        }}
      />
    </Tab.Navigator>
  );
}

/**
 * Simple Tab Icon Component
 */
import {Text} from 'react-native';

function TabIcon({icon, color}: {icon: string; color: string}) {
  return <Text style={{fontSize: 24, color}}>{icon}</Text>;
}

/**
 * Root App Component
 */
function App(): JSX.Element {
  useEffect(() => {
    // Initialize all services on app start
    EngineService.initialize().catch(error => {
      console.error('Failed to initialize services:', error);
    });

    // Set status bar style
    StatusBar.setBarStyle('light-content');
    if (Platform.OS === 'android') {
      StatusBar.setBackgroundColor(COLORS.BACKGROUND);
    }

    // Cleanup on unmount
    return () => {
      EngineService.stop().catch(error => {
        console.error('Failed to stop services:', error);
      });
    };
  }, []);

  return (
    <Provider store={store}>
      <NavigationContainer
        theme={{
          dark: true,
          colors: {
            primary: COLORS.PRIMARY,
            background: COLORS.BACKGROUND,
            card: COLORS.SURFACE,
            text: COLORS.TEXT_PRIMARY,
            border: COLORS.GLASS_BORDER,
            notification: COLORS.ERROR,
          },
        }}>
        <Stack.Navigator
          screenOptions={{
            headerStyle: {
              backgroundColor: COLORS.SURFACE,
              borderBottomColor: COLORS.GLASS_BORDER,
              borderBottomWidth: 1,
            },
            headerTintColor: COLORS.TEXT_PRIMARY,
            headerTitleStyle: {
              fontWeight: 'bold',
              fontSize: 18,
            },
          }}>
          <Stack.Screen
            name="Main"
            component={MainTabs}
            options={{headerShown: false}}
          />
          <Stack.Screen
            name="SandboxViewer"
            component={SandboxViewerScreen}
            options={{
              title: 'Sandbox Analysis',
              headerShown: true,
            }}
          />
        </Stack.Navigator>
      </NavigationContainer>
    </Provider>
  );
}

export default App;
