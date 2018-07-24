pragma solidity ^0.4.24;

import "./MultiSigDocument.sol";
import "./lib/strings.sol";

contract MultiSigDocumentWithStorage is MultiSigDocument, ILockableStorage {
  using strings for *;
  string constant NULL_CHAR = '\u0000';
  //Data
  mapping (bytes32 => string) public entryStorage;
  // A long string contains all of the key allKeysInString
  /* string public allKeysInString; */

  string[] public entryKeys;
  bool public writable = false;

  constructor(
    address[] signers,
    address verifier,
    uint8 required,
    uint effectiveDurationInDay,
    uint offset,
    bytes buffer
    )
  MultiSigDocument(signers, verifier, required, effectiveDurationInDay, 30)
  public
  {
    setData(offset, buffer);
  }

  modifier entryNotExisted(string memory entryKey) {
    assert(bytes(entryStorage[entryKey.toSlice().keccak()]).length == 0);
    _;
  }

  modifier entryExisted(string memory entryKey) {
    assert(bytes(entryStorage[entryKey.toSlice().keccak()]).length != 0);
    _;
  }
  modifier isWritable() {
    assert(writable);
    _;
  }
  event LogString(uint l1, string s1, string  s2);
  function setData(uint offset, bytes memory buffer)
    internal
  {
    while(offset > 0) {

      uint size;
      assembly {
         size := mload(add(buffer, offset))
      }
      string memory strKey = new string(size);
      writeBytesToString(offset, buffer, bytes(strKey));
      offset -= sizeOfString(strKey);
      assembly {
         size := mload(add(buffer, offset))
      }
      string memory strVal = new string(size);
      writeBytesToString(offset, buffer, bytes(strVal));
      offset -= sizeOfString(strVal);

      string memory strippedVal = strVal.toSlice().split(NULL_CHAR.toSlice()).toString();
      entryStorage[keccak256(abi.encodePacked(strKey))] = strippedVal;

      entryKeys.push(strKey.toSlice().split(NULL_CHAR.toSlice()).toString());
    }
  }

  function sizeOfString(string _in)
    internal
    pure
    returns(uint _size)
  {
      _size = bytes(_in).length / 32;
       if(bytes(_in).length % 32 != 0)
          _size++;

      _size++;
      _size *= 32;
  }

  function writeBytesToString(uint offset, bytes buffer, bytes output)
    internal
    pure
  {
    uint size = 32;
    assembly {
      let word_count
      size := mload(add(buffer, offset))
      word_count := add(div(size,32), 1)
      if gt(mod(size, 32), 0) {
        word_count := add(word_count,1)
      }
      for { let i := 0 } lt(i, word_count) { i := add(i, 1) } {
        mstore(add(output,mul(i, 0x20)),mload(add(buffer,offset)))
        offset:= sub(offset, 32)
      }
    }
  }

  function getAllKeys()
    public
    view
    returns (string memory out1)
  {
    for(uint32 i = 0 ; i < entryKeys.length; i++)
    {
      out1 = out1.toSlice().concat(
        entryKeys[i].toSlice()).toSlice().concat(";".toSlice());
    }
  }

  function getAllValues()
    public
    view
    returns (string memory out1)
  {
    for(uint32 i = 0 ; i < entryKeys.length; i++)
    {
      string memory s = entryStorage[entryKeys[i].toSlice().keccak()];
      out1 = out1.toSlice().concat(s.toSlice());
    }
  }

  function getProofHash()
    public
    view
    returns (bytes32)
  {
    return keccak256(abi.encodePacked(getAllValues()));
  }

  function addEntry(string memory key, string value)
    public
    isWritable()
    entryNotExisted(key)
    beforeModificationDeadline()
    onlyIssuer()
  {
    entryStorage[key.toSlice().keccak()] = value;
    entryKeys.push(key);
    emit EntrySet(address(this), key);
  }

  function updateEntry(string memory key, string value)
    public
    isWritable()
    beforeModificationDeadline()
    entryExisted(key)
    onlyIssuer()
  {
    entryStorage[key.toSlice().keccak()] = value;
    emit EntrySet(address(this), key);
  }

  function deleteEntry(string memory key)
    public
    beforeModificationDeadline()
    isWritable()
    onlyIssuer()
  {
    delete entryStorage[key.toSlice().keccak()];
    emit EntryDeleted(address(this), key);
  }

  function changeWritePermission(bool _writable, string memory key)
    public
    onlyVerifier()
  {
    writable = _writable;
    emit EntryUpdateRequest(address(this), key);
  }

  function getEntry(string memory key)
    public
    view
    returns (string)
  {
    return entryStorage[key.toSlice().keccak()];
  }
  function getKKHash(string memory s1)
    public
    view
    returns (bytes32)
  {
    return keccak256(abi.encodePacked(entryStorage[s1.toSlice().keccak()]));
  }

  function deleteDocument()
      public
      isExpired()
      allowDelete()
      signerExists(msg.sender)
  {
      selfdestruct(issuer);
  }

  function deleteData()
      internal
  {

  }

  function () public {
    // fallback
  }

}
