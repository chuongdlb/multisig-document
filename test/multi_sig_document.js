import assertRevert from 'openzeppelin-solidity/test/helpers/assertRevert';


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

export const sign = (contractAddr, signer, dataHash = '') => (addr) => {
    // via: https://github.com/OpenZeppelin/zeppelin-solidity/pull/812/files
    // data need to be transode to hex string and remove '0x' value prior to the following
    const message = contractAddr.substr(2) + addr.substr(2) + dataHash;
    // ^ substr to remove `0x` because in solidity the address is a set of byes, not a string `0xabcd`
    const messageHash = web3.sha3(message, {encoding:'hex'});

    return web3.eth.sign(signer, messageHash);
};
export const getSignerWithPrivKey= (contract, signer, data = '', privKey) => (addr) => {
    // via: https://github.com/OpenZeppelin/zeppelin-solidity/pull/812/files
    // data need to be transode to hex string and remove '0x' value prior to the following
    const message = contract.address.substr(2) + addr.substr(2) + data;
    // ^ substr to remove `0x` because in solidity the address is a set of byes, not a string `0xabcd`

    return web3.eth.accounts.sign(web3.sha3(message, {encoding:'hex'}),privKey );
};
export const getMethodId = (methodName, ...paramTypes) => {
  // methodId is a sha3 of the first 4 bytes after 0x of 'method(paramType1,...)'
  return web3.sha3(`${methodName}(${paramTypes.join(',')})`).substr(2, 8);
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
const SECONDS_IN_A_DAY = 86400;
const SECONDS_IN_A_YEAR = 31536000;
// contract('MockMultiSigDocumentWithStorage', ([issuer, signerA, signerB, verifier, anyone, newSigner]) => {
//
// });
contract('MockMultiSigDocumentWithStorage', ([issuer, signerA, signerB, verifier,anyone, newSigner]) => {

  let mockDocument = null;

  const signers = [signerA, signerB];
  const requiredSignatures = 2;
  const validDays = 365;
  const invalidDays = 22;

  const data = {
    "DocumentType": "Labor Contract",
    "DocumentName": "Contract of Hiring BackEnd Developer",
    "Issuer": "UIT Lab",
    "Beneficiary": "Mr.Chuong Dang",
    "ValidTime": "2018-2019"
  }

  var tmpData = {
    "DocumentType": "Labor Contract",
    "DocumentName": "Contract of Hiring Blockchain Engineer",
    "Issuer": "UIT Lab",
    "Beneficiary": "Chuong Dang",
    "ValidTime": "2018-2019"
  }

  const appendData = {
    "WorkingHoursPerWeek": "24"
  }
  const dataInBytes = documentJsonToHex(data);
  const keyStr = "ValidTime;Beneficiary;Issuer;DocumentName;DocumentType;";
  const updatingData = "Contract of Hiring Blockchain Researcher";


  before(async function() {

    mockDocument = await MockMultiSigDocumentWithStorage.new(signers, verifier, requiredSignatures, validDays,dataInBytes.length, dataInBytes.hex);
    // const tx = await mockDocument.setData(dataInBytes.length, dataInBytes.hex);
    // const {logs} = tx;
    // logs.forEach(function(log){console.log(log.args.l1.toNumber());  console.log(log);});
    this.validDaysInHex = stripAndPadHexValue(web3.toHex(validDays),32);
    this.checkValidSignatureFromSignerId = getMethodId('sign', 'address', 'bytes');
    tmpData.DocumentName = updatingData;
    console.log(mockDocument.address);
    this.combineProof = Object.values(tmpData).reverse().join("").concat(appendData.WorkingHoursPerWeek);
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


  it("should successfully deployed!", async function() {
    assert.equal(await mockDocument.numOfRequiredSignature(), requiredSignatures +1)
    assert.equal(await mockDocument.verified(), false);
    assert.equal(await mockDocument.validDays(), validDays);
    assert.equal(await mockDocument.getAllKeys(), keyStr);

    var revocationDeadline = await mockDocument.allowModificationDeadline();
    var deadline = new Date(revocationDeadline*1000);
    console.log(`     AllowModificationDeadline :`+ deadline.toString());
    var expirationTs = await mockDocument.expiration();
    var expiration = new Date(expirationTs*1000);
    console.log(`     Document expiration:` + expiration.toString());
  });

  it("should match all entries", async function() {

    assert.equal(await mockDocument.getEntry(Object.keys(data)[0]), data.DocumentType);
    assert.equal(await mockDocument.getEntry(Object.keys(data)[1]), data.DocumentName);
    assert.equal(await mockDocument.getEntry(Object.keys(data)[2]), data.Issuer);
    assert.equal(await mockDocument.getEntry(Object.keys(data)[3]), data.Beneficiary);
    assert.equal(await mockDocument.getEntry(Object.keys(data)[4]), data.ValidTime);

  });
  it("should match all hashes", async function() {
    assert.equal(await mockDocument.getKKHash(Object.keys(data)[0]), web3.sha3(web3.toHex(data.DocumentType).substr(2), {encoding: 'hex'}));
    assert.equal(await mockDocument.getKKHash(Object.keys(data)[1]), web3.sha3(data.DocumentName));
    assert.equal(await mockDocument.getKKHash(Object.keys(data)[2]), web3.sha3(data.Issuer));
    assert.equal(await mockDocument.getKKHash(Object.keys(data)[3]), web3.sha3(data.Beneficiary));
    assert.equal(await mockDocument.getKKHash(Object.keys(data)[4]), web3.sha3(data.ValidTime));

  });
  it("should allow verifier to request update an entry.", async function() {

    let tx = await transaction(mockDocument.changeWritePermission(true, Object.keys(data)[1], {from: verifier}), false);
    let block = await web3.eth.getBlock(tx.receipt.blockNumber);
    const {logs} = tx;
    assert.strictEqual(logs.length, 1);
    assert.strictEqual(logs[0].event, "EntryUpdateRequest");
    assert.strictEqual(logs[0].args.entryKey, Object.keys(data)[1]);

  });

  it("should allow issuer to UPDATE an entry", async function() {

    let tx = await transaction(mockDocument.updateEntry(Object.keys(data)[1], updatingData , {from: issuer}), false);
    const {logs} = tx;
    assert.strictEqual(logs.length, 1);
    assert.strictEqual(logs[0].event, "EntrySet");
    assert.strictEqual(logs[0].args.entryKey, Object.keys(data)[1]);
    assert.strictEqual(await mockDocument.getEntry(Object.keys(data)[1]), updatingData);

  });
  it("should allow issuer to ADD a new entry", async function() {

    let tx = await transaction(mockDocument.addEntry(Object.keys(appendData)[0], appendData.WorkingHoursPerWeek, {from: issuer}), false);
    const {logs} = tx;
    assert.strictEqual(logs.length, 1);
    assert.strictEqual(logs[0].event, "EntrySet");
    assert.strictEqual(logs[0].args.entryKey, Object.keys(appendData)[0]);
    assert.strictEqual(await mockDocument.getEntry(Object.keys(appendData)[0]), appendData.WorkingHoursPerWeek);
    const v = await mockDocument.getAllKeys();
    console.log(v);
    v.should.eq(keyStr.concat(Object.keys(appendData)[0]+";"));
  });

  it("should not allow issuer to set/update/delete an entry without writable permission", async function() {
    await transaction(mockDocument.changeWritePermission(false, "", {from: verifier}), false);
    assert.strictEqual(await mockDocument.writable(), false);
    try {
       await mockDocument.deleteEntry(Object.keys(data)[1], {from: issuer});
       assert.fail();
    }
    catch(err) {

    }
  });
  it(`fast-forward to the future to past the allowModificationDeadline, should not allow to modify`, async function() {
    await transaction(mockDocument.changeWritePermission(true, "", {from: verifier}), false);

    await timeTravel(30*SECONDS_IN_A_DAY + SECONDS_IN_A_DAY);

    try {
      await mockDocument.updateEntry(Object.keys(data)[0], "123" ,{from: issuer });
    }
    catch(err) {
      assert.ok(/revert/.test(err.message));
    }

  })

  it("should collect enough digital signatures.", async function() {

    const h = await mockDocument.getProofHash();
    // assert.equal(h, web3.sha3(this.combineProof)); // the finalized data hash
    var sig1 = getSigner(mockDocument,signerA, h.substr(2) )(verifier);
    var sig2 = getSigner(mockDocument,signerB, h.substr(2) )(verifier);
    var sig3 = getSigner(mockDocument,issuer, h.substr(2) )(verifier);

    await transaction(mockDocument.signDocument(sig1), false);
    await transaction(mockDocument.signDocument(sig2), false);
    await transaction(mockDocument.signDocument(sig3), false);

    assert.deepEqual(await mockDocument.signerProperties(signerA), [true, true, false]);
    assert.deepEqual(await mockDocument.signerProperties(signerB), [true, true, false]);
    assert.deepEqual(await mockDocument.signerProperties(issuer), [true, true, false]);


    const valid = await mockDocument.isEnoughSignature();
    valid.should.eq(true);
    const v  = await mockDocument.verified();
    v.should.eq(false);
  });
  //
  it('should not submit signature with false proof ', async function () {
    try {
      await mockDocument.signDocument(this.invalidSignatures[1]);
      assert.fail();
    }
    catch(err) {
       assert.ok(/revert/.test(err.message));
    }
  });
  it('should not submit invalid signature from anyone.', async function () {
    try {
      await mockDocument.signDocument(this.invalidSignatures[0]);
      assert.fail();
    }
    catch(err) {
       assert.ok(/revert/.test(err.message));
    }
  })

  it('should be able to verify the MultiSigDocument', async function() {
    await mockDocument.verifyDocument ({from: verifier});
    const v = await mockDocument.verified();
    v.should.eq(true);
  })

  it(`fast-forward to the future to past ${validDays} days, should be able to revokeDocument`,
    async function() {
      await timeTravel(SECONDS_IN_A_YEAR + SECONDS_IN_A_DAY);
      await mockDocument.revokeDocument({from: verifier});
      const activated = await mockDocument.verified();
      activated.should.eq(false);
  })

  it("allow delete document after revocation.", async function() {

    // const promise = await mockDocument.addSignature(signerA, sigA);
    await transaction(mockDocument.submitDeleteConfirmation(true, this.deleteSig[0]), false);
    await transaction(mockDocument.submitDeleteConfirmation(true, this.deleteSig[1]), false);
    await transaction(mockDocument.submitDeleteConfirmation(true, this.deleteSig[2]), false);

    assert.deepEqual(await mockDocument.signerProperties(signerA), [true, true, true]);
    assert.deepEqual(await mockDocument.signerProperties(signerB), [true, true, true]);
    assert.deepEqual(await mockDocument.signerProperties(issuer), [true, true, true]);


    const valid = await mockDocument.checkDeleteConfirmations();
    valid.should.eq(true);
    const v  = await mockDocument.deleteDocument({from:signerA});

  });
});
