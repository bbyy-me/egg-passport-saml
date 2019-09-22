# egg-passport-saml

## Install

```bash
npm i @bbyy/egg-passport-saml --save
```

## Usage

```js
// {app_root}/config/plugin.js
exports.passportSaml = {
  enable: true,
  package: '@bbyy/egg-passport-saml',
};
```

## Configuration

```js
// {app_root}/config/config.default.js
exports.passportSaml = {
};
```

see [config/config.default.js](config/config.default.js) for more detail.
依赖egg的sessionStore保存需要的缓存。

## License

[MIT](LICENSE)
