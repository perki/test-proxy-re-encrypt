const webpack = require('webpack');
const CopyPlugin = require('copy-webpack-plugin');
const path = require('path');

module.exports = [
  {
    mode: 'production',
    entry: {
      app: {
        import: './web/index.js',
        library: {
          name: 'lib',
          type: 'var'
        }
      }
    },
    output: {
      filename: 'app.js',
      path: distPath(),
      //webassemblyModuleFilename: 'app.wasm',
      //globalObject: "typeof self !== 'object' ? self : this"
    },
    devtool: 'source-map',
    experiments: { asyncWebAssembly: true },
    resolve: {
      fallback: {
        crypto: require.resolve('crypto-browserify'),
        stream: require.resolve('stream-browserify'),
        buffer: require.resolve('buffer/')
      },
      alias: {
        '@ironcorelabs/recrypt-node-binding': require.resolve('@ironcorelabs/recrypt-wasm-binding'),
      }
    },
    plugins: [
      new webpack.ProvidePlugin({
        Buffer: ['buffer', 'Buffer']
      }),
      new CopyPlugin({
        patterns: [
          { from: 'web/index.html', to: './' },
        ],
      }),
    ]
  },
  { // browser test suite (ES6)
    mode: 'development',
    entry: {
      'browser-tests': './web/browser-tests.js'
    },
    output: {
      filename: 'tests.js',
      path: distPath(),
      //webassemblyModuleFilename: 'tests.wasm'
      //globalObject: "typeof self !== 'object' ? self : this" // need by mocha for some reasons
    },
    plugins: [
      new webpack.ProvidePlugin({
        Buffer: ['buffer', 'Buffer'],
        process: 'process/browser',
      }),
      new CopyPlugin({
        patterns: [
          { from: 'web/browser-test.html', to: distPath('tests.html') }
        ]
      })
    ],
    experiments: {
      asyncWebAssembly: true
    },
    devtool: 'source-map',
    resolve: {
      fallback: {
        fs: false,
        path: false,
        crypto: require.resolve('crypto-browserify'),
        stream: require.resolve('stream-browserify'),
        buffer: require.resolve('buffer/'),
        util: require.resolve('util/'),
        'process/browser': require.resolve('process/browser')
      },
      alias: {
        '@ironcorelabs/recrypt-node-binding': require.resolve('@ironcorelabs/recrypt-wasm-binding'),
      }
    }
  }];


function distPath (...subPath) {
  return path.join(__dirname, 'docs', ...subPath);
}