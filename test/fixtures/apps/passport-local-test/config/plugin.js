'use strict';
const join = require('path').join;
module.exports = {
  redis: {
    enable: true,
    package: 'egg-redis',
  },
  // sessionRedis:{
  //   enable:true,
  //   package:'egg-session-redis'
  // },
  passport: {
    enable: true,
    package: 'egg-passport',
  },
  passportSaml: {
    enable: true,
    path: join(__dirname, '../../../../../'),
  },
  sessionRedis: {
    enable: true,
    package: 'egg-session-redis',
  },
};
