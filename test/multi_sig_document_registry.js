import assertRevert from 'openzeppelin-solidity/test/helpers/assertRevert';
// import  { signHex } from 'openzeppelin-solidity/test/helpers/sign';
import utils from 'ethereumjs-util';

var MultiSigDocumentABI = [
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
        "indexed": false,
        "name": "l1",
        "type": "uint256"
      },
      {
        "indexed": false,
        "name": "s1",
        "type": "string"
      }
    ],
    "name": "LogString",
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
    "constant": false,
    "inputs": [
      {
        "name": "offset",
        "type": "uint256"
      },
      {
        "name": "buffer",
        "type": "bytes"
      }
    ],
    "name": "setData",
    "outputs": [],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
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
const BigNumber = web3.BigNumber;
const id = '0';
const jsonrpc = '2.0';


require('chai')
  .use(require('chai-as-promised'))
  .use(require('chai-bignumber')(BigNumber))
  .should();

  async function transaction(promise, mustfail) {
        let tx = await promise;
        const txInfo = await web3.eth.getTransaction(tx.tx);
        const gasCost  = txInfo.gasPrice.mul(tx.receipt.gasUsed);

        console.log(`      gasUsed: ${tx.receipt.gasUsed} (Gas),
      gasCost: ${web3.fromWei(gasCost.toString(),'ether')} (Ether)`);

        if (mustfail) {
            if (tx.receipt.status !== "0x0")
                throw new Error("The transaction should have failed but did not.");
        }
        else {
            if (tx.receipt.status === "0x0")
                throw new Error("The transaction failed but should not.");
        }

        return tx;
  }
  //
  export const getSigner = (contract, signer, dataHash = '') => (addr) => {
      // via: https://github.com/OpenZeppelin/zeppelin-solidity/pull/812/files
      // data need to be transode to hex string and remove '0x' value prior to the following
      const message = contract.address.substr(2) + addr.substr(2) + dataHash;
      // ^ substr to remove `0x` because in solidity the address is a set of byes, not a string `0xabcd`
      const messageHash = web3.sha3(message, {encoding:'hex'});

      return web3.eth.sign(signer, messageHash);
  };


  export const stripAndPadHexValue = (hexVal, sizeInBytes, start = true) => {
    // strip 0x from the font and pad with 0's for
    const strippedHexVal = hexVal.substr(2);
    return start ? strippedHexVal.padStart(sizeInBytes * 2, 0) : strippedHexVal.padEnd(sizeInBytes * 2, 0);
  };
  export const padHexValueForString = (strVal) => {
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
export const documentJsonToHex = (data) => {
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
         padHexValueForString(strVal)
        + stripAndPadHexValue(web3.toHex(key), 32, false)
        + stripAndPadHexValue(web3.toHex(key.length), 32);
      }
  }
  return {length: Math.floor(dataInBytes.length/2), hex: "0x"+dataInBytes};
}

export const combineProof = (data) => {
  var retVal = '';
  Object.keys(data).length
  return retVal;
}

const send = (method, params = []) =>
  web3.currentProvider.send({ id, jsonrpc, method, params })

export const timeTravel = async seconds => {
  await send('evm_increaseTime', [seconds])
  await send('evm_mine')
}

const MockMultiSigDocumentWithStorage = artifacts.require("./MultiSigDocumentWithStorage.sol");
const MultiSigDocumentRegistry = artifacts.require("./MultiSigDocumentRegistry.sol");
const SECONDS_IN_A_DAY = 86400;
const SECONDS_IN_A_YEAR = 31536000;

contract('MultiSigDocumentRegistry', ([issuer, verifier, signerA, signerB, anyone]) => {

  //const keyArr = ['DocumentType', 'DocumentName', 'Issuer', 'Beneficiary', 'ValidTime'];
  //const valueArr = ['Labor Contract','Contract of Hiring Developer','Rosen R&D Lab', 'Mr. Robot','2018-2019'];
  //const valueArr2= ['Labor Contract','Contract of Hiring Part-time Software Engineer','Rosen R&D Lab', 'Mr. Dark','2018-2019'];

  const data = {
    "DocumentType": "Labor Contract",
    "DocumentName": "Contract of Hiring BackEnd Developer",
    "Issuer": "Rosen-UIT Lab",
    "Beneficiary": "Mr.Chuong Dang",
    "ValidTime": "2018-2019"
  }

  var data2 = {
    "DocumentType": "Research Contract",
    "DocumentName": "Contract of Hiring Blockchain Researcher",
    "Issuer": "Rosen-UIT Lab",
    "Beneficiary": "Mr.Chuong Dang",
    "ValidTime": "2018-2019"
  }

  const appendData = {
    "WorkingHoursPerWeek": "24"
  }
  const dataInBytes = documentJsonToHex(data);
  const dataInBytes2 = documentJsonToHex(data2);
  const keyStr = "ValidTime;Beneficiary;Issuer;DocumentName;DocumentType;";
  const updatingData = "Contract of Hiring Blockchain Engineer";

  let registry = null;
  let mockDocument = null;

  const signers = [signerA, signerB];
  const requiredSignatures = 2;
  const validDays = 365;
  const invalidDays = 22;

  before(async function() {
    registry = await MultiSigDocumentRegistry.new();
    mockDocument = await MockMultiSigDocumentWithStorage.new(signers, verifier, requiredSignatures, validDays,dataInBytes.length, dataInBytes.hex);




  });
  it("should register verifier", async function() {
    await registry.registerVerifier("University of Information and Technology","uit.edu.vn",{from: verifier});
    assert.deepEqual(await registry.verifierInfo.call(verifier), [true, "University of Information and Technology","uit.edu.vn"]);

  });
  it("should set document!", async function() {
    const tx = await transaction(registry.setDocument(mockDocument.address), false);

    console.log('Document addr: ' + mockDocument.address);

    const docAddr = await registry.docVault.call(issuer,0);
    docAddr.should.eq(mockDocument.address);

    const docType = await registry.getEntry(issuer, 0, Object.keys(data)[0]);
    docType.should.eq(data.DocumentType);
  });
  it("should create document", async function() {
    console.log(dataInBytes2.length);
    console.log(dataInBytes2.hex);

    const tx = await transaction(registry
    .createDocument(signers, verifier, requiredSignatures, validDays,dataInBytes2.length, dataInBytes2.hex),
    false);
    const {logs} = tx;
    console.log(logs[0]);
    // const tmpAddr = await registry.docVault.call(issuer,1);
    // docAddr.should.eq(tmpAdr);

    const docName = await registry.getEntry(issuer, 1, Object.keys(data2)[1]);
    docName.should.eq(data2.DocumentName);
  });
  it("should time travel to pass 30 days & sign", async function() {
    await timeTravel(30*SECONDS_IN_A_DAY + SECONDS_IN_A_DAY);
    // var contract = web3.eth.contract(MultiSigDocumentABI);
    // var doc = contract.at('0x3c89f20c6cf8063e2c15f01ab0864a1198021f77');
    const hash = await mockDocument.getProofHash();
    console.log(hash);
    var issuerSig = getSigner(mockDocument, issuer, hash.substr(2))(verifier);
    var signerSigA = getSigner(mockDocument, signerA, hash.substr(2))(verifier);
    var signerSigB = getSigner(mockDocument, signerB, hash.substr(2))(verifier);

    console.log(issuerSig);
    console.log(signerSigA);
    console.log(signerSigB);

    // await mockDocument.signDocument(issuerSig);
    // await mockDocument.signDocument(signerSigA);
    // await mockDocument.signDocument(signerSigB);


  });


});
