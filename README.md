# egg-passport-local

## Install

```bash
npm i @ustack/egg-passport-saml --save
```

## Usage

```js
// {app_root}/config/plugin.js
exports.passportSaml = {
  enable: true,
  package: '@ustack/egg-passport-saml',
};
```

## Configuration

```js
// {app_root}/config/config.default.js
exports.passportSaml = {
};
```

see [config/config.default.js](config/config.default.js) for more detail.

如果挂载路由，插件提供的controller中需要用到ctx.model.Session。需要提前配置好这个

创建
查询
删除
修改

## License

[MIT](LICENSE)
