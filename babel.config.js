module.exports = {
  presets: ['module:metro-react-native-babel-preset'],
  plugins: [
    [
      'module-resolver',
      {
        root: ['./src'],
        extensions: ['.ios.js', '.android.js', '.js', '.ts', '.tsx', '.json'],
        alias: {
          '@': './src',
          '@ui': './src/ui',
          '@engine': './src/engine',
          '@models': './src/models',
          '@database': './src/database',
          '@utils': './src/utils',
          '@native': './native',
        },
      },
    ],
    'react-native-reanimated/plugin',
  ],
};
