// var DocLib = artifacts.require("./lib/DocLib.sol");
var tmpData = {
  "DocumentType": "Labor Contract",
  "DocumentName": "Contract of Hiring Blockchain Engineer",
  "Issuer": "UIT Lab",
  "Beneficiary": "Chuong Dang",
  "ValidTime": "2018-2019"
}
const MultiSigDocumentWithStorageABI = [
  {
    "constant": true,
    "inputs": [],
    "name": "issuer",
    "outputs": [
      {
        "name": "",
        "type": "address"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "numOfRequiredSignature",
    "outputs": [
      {
        "name": "",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [],
    "name": "revokeDocument",
    "outputs": [],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "verifier",
    "outputs": [
      {
        "name": "",
        "type": "address"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "confirmedDeleted",
        "type": "bool"
      },
      {
        "name": "sig",
        "type": "bytes"
      }
    ],
    "name": "submitDeleteConfirmation",
    "outputs": [],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "addr",
        "type": "address"
      }
    ],
    "name": "isVerifier",
    "outputs": [
      {
        "name": "",
        "type": "bool"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "validDays",
    "outputs": [
      {
        "name": "",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "checkDeleteConfirmations",
    "outputs": [
      {
        "name": "",
        "type": "bool"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "finalizedSigConfirmations",
    "outputs": [
      {
        "name": "",
        "type": "uint8"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "",
        "type": "address"
      }
    ],
    "name": "signerProperties",
    "outputs": [
      {
        "name": "IsSigner",
        "type": "bool"
      },
      {
        "name": "IsSigned",
        "type": "bool"
      },
      {
        "name": "DeleteConfirmed",
        "type": "bool"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "expiration",
    "outputs": [
      {
        "name": "",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "",
        "type": "bytes32"
      }
    ],
    "name": "entryStorage",
    "outputs": [
      {
        "name": "",
        "type": "string"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [],
    "name": "verifyDocument",
    "outputs": [],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "MAX_SIGNER_COUNT",
    "outputs": [
      {
        "name": "",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "isVerified",
    "outputs": [
      {
        "name": "",
        "type": "bool"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "addr",
        "type": "address"
      }
    ],
    "name": "isIssuer",
    "outputs": [
      {
        "name": "",
        "type": "bool"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "isEnoughSignature",
    "outputs": [
      {
        "name": "",
        "type": "bool"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "allowModificationDeadline",
    "outputs": [
      {
        "name": "",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "autoActivation",
    "outputs": [
      {
        "name": "",
        "type": "bool"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "createdTime",
    "outputs": [
      {
        "name": "",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "verified",
    "outputs": [
      {
        "name": "",
        "type": "bool"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "",
        "type": "uint256"
      }
    ],
    "name": "entryKeys",
    "outputs": [
      {
        "name": "",
        "type": "string"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "sig",
        "type": "bytes"
      }
    ],
    "name": "signDocument",
    "outputs": [],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "writable",
    "outputs": [
      {
        "name": "",
        "type": "bool"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "deleteConfirmations",
    "outputs": [
      {
        "name": "",
        "type": "uint8"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "newRequiredNumber",
        "type": "uint256"
      }
    ],
    "name": "changeNumberOfRquiredSignatures",
    "outputs": [],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "name": "signers",
        "type": "address[]"
      },
      {
        "name": "verifier",
        "type": "address"
      },
      {
        "name": "required",
        "type": "uint8"
      },
      {
        "name": "effectiveDurationInDay",
        "type": "uint256"
      },
      {
        "name": "offset",
        "type": "uint256"
      },
      {
        "name": "buffer",
        "type": "bytes"
      }
    ],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "constructor"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "name": "document",
        "type": "address"
      },
      {
        "indexed": false,
        "name": "entryKey",
        "type": "string"
      }
    ],
    "name": "EntrySet",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "name": "document",
        "type": "address"
      },
      {
        "indexed": false,
        "name": "entryKey",
        "type": "string"
      }
    ],
    "name": "EntryDeleted",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "name": "document",
        "type": "address"
      },
      {
        "indexed": false,
        "name": "entryKey",
        "type": "string"
      }
    ],
    "name": "EntryUpdateRequest",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "name": "verifier",
        "type": "address"
      },
      {
        "indexed": true,
        "name": "doc",
        "type": "address"
      }
    ],
    "name": "Verification",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "name": "verifier",
        "type": "address"
      },
      {
        "indexed": true,
        "name": "doc",
        "type": "address"
      }
    ],
    "name": "Revocation",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": false,
        "name": "submitter",
        "type": "address"
      }
    ],
    "name": "LogInvalidSignatureSubmission",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": false,
        "name": "oldNum",
        "type": "uint256"
      },
      {
        "indexed": true,
        "name": "newNum",
        "type": "uint256"
      }
    ],
    "name": "LogNumOfRequiredSignatureChanged",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "name": "document",
        "type": "address"
      },
      {
        "indexed": true,
        "name": "verifier",
        "type": "address"
      }
    ],
    "name": "DocumentSigned",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "name": "document",
        "type": "address"
      },
      {
        "indexed": true,
        "name": "verifier",
        "type": "address"
      }
    ],
    "name": "DeleteDocumentConfirmation",
    "type": "event"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "getAllKeys",
    "outputs": [
      {
        "name": "out1",
        "type": "string"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "getAllValues",
    "outputs": [
      {
        "name": "out1",
        "type": "string"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "getProofHash",
    "outputs": [
      {
        "name": "",
        "type": "bytes32"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "key",
        "type": "string"
      },
      {
        "name": "value",
        "type": "string"
      }
    ],
    "name": "addEntry",
    "outputs": [],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "key",
        "type": "string"
      },
      {
        "name": "value",
        "type": "string"
      }
    ],
    "name": "updateEntry",
    "outputs": [],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "key",
        "type": "string"
      }
    ],
    "name": "deleteEntry",
    "outputs": [],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "_writable",
        "type": "bool"
      },
      {
        "name": "key",
        "type": "string"
      }
    ],
    "name": "changeWritePermission",
    "outputs": [],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "key",
        "type": "string"
      }
    ],
    "name": "getEntry",
    "outputs": [
      {
        "name": "",
        "type": "string"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "s1",
        "type": "string"
      }
    ],
    "name": "getKKHash",
    "outputs": [
      {
        "name": "",
        "type": "bytes32"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [],
    "name": "deleteDocument",
    "outputs": [],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  }
];

const requiredSignatures = 2;
const validDays = 365;
const documentJsonToHex = (data) => {
  var dataInBytes ="";
  for (var key in data) {
      if (data.hasOwnProperty(key)) {
        var strVal = data[key];
        var strValLengthInBytes = 32 * Math.floor(strVal.length / 32) + (strVal.length % 32 > 0 ? 32: 0);
        if(strValLengthInBytes > 32) {
          strVal.slice(32 * Math.floor(strVal.length / 32));
        }
        console.log("Value: "+ strVal+ " Length: "+ strValLengthInBytes)
        dataInBytes +=
        stripAndPadHexValue(web3.toHex(key), 32, false)
        + stripAndPadHexValue(web3.toHex(key.length), 32)
        + padHexValueForString(strVal);

      }
  }
  return {length: Math.floor(dataInBytes.length/2), hex: "0x"+dataInBytes};
}
const stripAndPadHexValue = (hexVal, sizeInBytes, start = true) => {
  // strip 0x from the font and pad with 0's for
  const strippedHexVal = hexVal.substr(2);
  return start ? strippedHexVal.padStart(sizeInBytes * 2, 0) : strippedHexVal.padEnd(sizeInBytes * 2, 0);
};

const padHexValueForString = (strVal) => {
  // strip 0x from the font and pad with 0's for
  var strValLengthInBytes = 32 * Math.floor(strVal.length / 32) + (strVal.length % 32 > 0 ? 32: 0);

  if(strVal.length > 32) {
    // Split into 32-byte chunk
    var strArr = strVal.match(/.{1,32}/g).reverse();
    console.log(strArr);
    var tmpHex = "";
    strArr.forEach(function(e) { tmpHex += stripAndPadHexValue(web3.toHex(e), 32, false); });
    return (tmpHex + stripAndPadHexValue(web3.toHex(strValLengthInBytes), 32));
  }

  return (stripAndPadHexValue(web3.toHex(strVal), strValLengthInBytes, false)
        + stripAndPadHexValue(web3.toHex(strValLengthInBytes), 32));

};
var hexData = documentJsonToHex(tmpData);
var signers = ['0xBc80Ca2C9913E9B3980943C9b48A78c86Db2F6f1','0x80E36B80ef6fc0239f83f34d1F140E74dF0c44CC'];
var issuer = '0x9Ad54484D10D345897c17112D7e77543A43212AD';
var verifier = '0x603695254bdCb221C0353911F7E21bB56F744FAa';

var MultiSigDocument = artifacts.require("./MultiSigDocumentWithStorage.sol");
var MultiSigDocumentRegistry = artifacts.require("./MultiSigDocumentRegistry.sol");
module.exports = function(deployer) {

  deployer.deploy(MultiSigDocument,
                    // constructor params
                    signers, verifier,
                    requiredSignatures,
                    validDays,
                    hexData.length, hexData.hex);
  deployer.deploy(MultiSigDocumentRegistry);

};
