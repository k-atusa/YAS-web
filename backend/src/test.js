const jwt = require('jsonwebtoken');
const token = jwt.sign({ sub: '123' }, 'test-secret');
console.log(token);
