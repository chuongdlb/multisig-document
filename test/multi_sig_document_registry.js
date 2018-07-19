import assertRevert from 'openzeppelin-solidity/test/helpers/assertRevert';
// import  { signHex } from 'openzeppelin-solidity/test/helpers/sign';
import utils from 'ethereumjs-util';


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
  export const getSigner = (contract, signer, data = '') => (addr) => {
      // via: https://github.com/OpenZeppelin/zeppelin-solidity/pull/812/files
      // data need to be transode to hex string and remove '0x' value prior to the following
      const message = contract.address.substr(2) + addr.substr(2) + data;
      // ^ substr to remove `0x` because in solidity the address is a set of byes, not a string `0xabcd`

      return web3.eth.sign(signer, web3.sha3(message, {encoding:'hex'}));
  };

  export const getSignerWithPrivKey= (contract, signer, data = '', privKey) => (addr) => {
      // via: https://github.com/OpenZeppelin/zeppelin-solidity/pull/812/files
      // data need to be transode to hex string and remove '0x' value prior to the following
      const message = contract.address.substr(2) + addr.substr(2) + data;
      // ^ substr to remove `0x` because in solidity the address is a set of byes, not a string `0xabcd`

      return web3.eth.accounts.sign(web3.sha3(message, {encoding:'hex'}),privKey );
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
        stripAndPadHexValue(web3.toHex(key), 32, false)
        + stripAndPadHexValue(web3.toHex(key.length), 32)
        + padHexValueForString(strVal);

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
    this.validDaysInHex = stripAndPadHexValue(web3.toHex(validDays),32);
    // tmpData.DocumentName = updatingData;

    console.log(this.combineProof);
    console.log(web3.sha3(this.combineProof));
    this.validSignatures = [
      getSigner(mockDocument, signerA, web3.sha3(this.combineProof).substr(2)) (verifier),
      getSigner(mockDocument, signerB, web3.sha3(this.combineProof).substr(2)) (verifier),
      getSigner(mockDocument, issuer,  web3.sha3(this.combineProof).substr(2)) (verifier)
    ];
    this.deleteSig = [
      getSigner(mockDocument, signerA, stripAndPadHexValue(web3.toHex(true),1))(''),
      getSigner(mockDocument, signerB, stripAndPadHexValue(web3.toHex(true),1))(''),
      getSigner(mockDocument, issuer,  stripAndPadHexValue(web3.toHex(true),1))(''),
    ]

    this.invalidSignatures = [
      getSigner(mockDocument, anyone, this.validDaysInHex)(verifier),
      getSigner(mockDocument, signerB, invalidDays)(verifier)
    ]

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
    const docAddr = await transaction(registry
    .createDocument(signers, verifier, requiredSignatures, validDays,dataInBytes2.length, dataInBytes2.hex),
    false);

    // const tmpAddr = await registry.docVault.call(issuer,1);
    // docAddr.should.eq(tmpAdr);

    const docName = await registry.getEntry(issuer, 1, Object.keys(data2)[1]);
    docName.should.eq(data2.DocumentName);
  });



});
