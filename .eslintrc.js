module.exports = {
  'env': {
    'browser': true,
    'es6': true,
  },
  'extends': [
    'samrap',
  ],
  'globals': {
    'Atomics': 'readonly',
    'SharedArrayBuffer': 'readonly',
  },
  'parserOptions': {
    'ecmaVersion': 2018,
    'sourceType': 'module',
  },
  'rules': {
    "max-len": [1, {"code": 120, "tabWidth": 4, "ignoreUrls": true, "ignoreComments": true}]
  },
};
