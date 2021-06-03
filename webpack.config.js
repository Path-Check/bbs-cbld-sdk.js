const path = require('path');

module.exports = {
  mode: "production",
  entry: "./lib/main.js",
  devtool: "source-map",
  output: {
    filename: 'bbs-cbld-sdk.min.js',
    path: path.resolve(__dirname, 'dist'),
    library: 'BBS_CBLD',
    libraryTarget: 'umd',
  },
  optimization: {
    minimize: true
  }
};