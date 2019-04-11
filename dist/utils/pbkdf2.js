"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

var _regenerator = _interopRequireDefault(require("@babel/runtime/regenerator"));

var _asyncToGenerator2 = _interopRequireDefault(require("@babel/runtime/helpers/asyncToGenerator"));

var _require = require('pbkdf2'),
    pbkdf2Async = _require.pbkdf2,
    pbkdf2Sync = _require.pbkdf2Sync;

var promisifiedPbkdf2 = function promisifiedPbkdf2(password, salt, iterations, length, algo) {
  return new Promise(function (resolveFunction, rejectFunction) {
    pbkdf2Async(password, salt, iterations, length, algo, function (error, response) {
      if (error) {
        rejectFunction(error);
      }

      resolveFunction(response);
    });
  });
};

var pbkdf2 =
/*#__PURE__*/
function () {
  var _ref = (0, _asyncToGenerator2["default"])(
  /*#__PURE__*/
  _regenerator["default"].mark(function _callee(password, salt, iterations, length, algo) {
    var result;
    return _regenerator["default"].wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            _context.prev = 0;
            _context.next = 3;
            return promisifiedPbkdf2(password, salt, iterations, length, algo);

          case 3:
            result = _context.sent;
            return _context.abrupt("return", result);

          case 7:
            _context.prev = 7;
            _context.t0 = _context["catch"](0);
            return _context.abrupt("return", pbkdf2Sync(password, salt, iterations, length, algo));

          case 10:
          case "end":
            return _context.stop();
        }
      }
    }, _callee, null, [[0, 7]]);
  }));

  return function pbkdf2(_x, _x2, _x3, _x4, _x5) {
    return _ref.apply(this, arguments);
  };
}();

module.exports = pbkdf2;