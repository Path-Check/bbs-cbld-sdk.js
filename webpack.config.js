const path = require('path');

module.exports = {
  mode: "production",
  entry: "./lib/main.js",
  devtool: "source-map",
  output: {
    filename: 'bbs-cborld.sdk.min.js',
    path: path.resolve(__dirname, 'dist'),
    library: 'BBS_CBORLD',
    libraryTarget: 'umd',
  },
  optimization: {
    minimize: false
  }
};