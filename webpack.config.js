const webpack = require('webpack');
const CopyPlugin = require("copy-webpack-plugin");
const path = require("path");

module.exports = {
    mode: 'production',
    entry: {
      app: ['./web/index.js'],
    },
    output: {
        filename: "[name].js",
        path: path.resolve(__dirname, 'docs'),
        globalObject: 'typeof self !== "object" ? self : this'
    },
    devtool: 'source-map',
    experiments: {
      asyncWebAssembly: true
    },
    plugins: [
      new webpack.ProvidePlugin({
           Buffer: ['buffer', 'Buffer']
      }),
      new CopyPlugin({
        patterns: [
          { from: "web/index.html", to: "./" },
        ],
      }),
    ],
};
