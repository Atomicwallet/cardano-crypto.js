"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

var _toConsumableArray2 = _interopRequireDefault(require("@babel/runtime/helpers/toConsumableArray"));

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime/helpers/createClass"));

var cbor = require('borc');

module.exports =
/*#__PURE__*/
function () {
  function CborIndefiniteLengthArray(elements) {
    (0, _classCallCheck2["default"])(this, CborIndefiniteLengthArray);
    this.elements = elements;
  }

  (0, _createClass2["default"])(CborIndefiniteLengthArray, [{
    key: "encodeCBOR",
    value: function encodeCBOR(encoder) {
      return encoder.push(Buffer.concat([Buffer.from([0x9f])].concat((0, _toConsumableArray2["default"])(this.elements.map(function (e) {
        return cbor.encode(e);
      })), [Buffer.from([0xff])])));
    }
  }]);
  return CborIndefiniteLengthArray;
}();