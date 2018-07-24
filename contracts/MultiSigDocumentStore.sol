pragma solidity ^0.4.24;

// File: contracts/lib/ECRecovery.sol

/**
 * @title Eliptic curve signature operations
 *
 * @dev Based on https://gist.github.com/axic/5b33912c6f61ae6fd96d6c4a47afde6d
 *
 * TODO Remove this library once solidity supports passing a signature to ecrecover.
 * See https://github.com/ethereum/solidity/issues/864
 *
 */

library ECRecovery {

  /**
   * @dev Recover signer address from a message by using their signature
   * @param hash bytes32 message, the hash is the signed message. What is recovered is the signer address.
   * @param sig bytes signature, the signature is generated using web3.eth.sign()
   */
  function recover(bytes32 hash, bytes sig)
    internal
    pure
    returns (address)
  {
    bytes32 r;
    bytes32 s;
    uint8 v;

    // Check the signature length
    if (sig.length != 65) {
      return (address(0));
    }

    // Divide the signature in r, s and v variables
    // ecrecover takes the signature parameters, and the only way to get them
    // currently is to use assembly.
    // solium-disable-next-line security/no-inline-assembly
    assembly {
      r := mload(add(sig, 32))
      s := mload(add(sig, 64))
      v := byte(0, mload(add(sig, 96)))
    }

    // Version of signature should be 27 or 28, but 0 and 1 are also possible versions
    if (v < 27) {
      v += 27;
    }

    // If the version is correct return the signer address
    if (v != 27 && v != 28) {
      return (address(0));
    } else {
      // solium-disable-next-line arg-overflow
      return ecrecover(hash, v, r, s);
    }
  }

  /**
   * toEthSignedMessageHash
   * @dev prefix a bytes32 value with "\x19Ethereum Signed Message:"
   * @dev and hash the result
   */
  function toEthSignedMessageHash(bytes32 hash)
    internal
    pure
    returns (bytes32)
  {
    // 32 is the length in bytes of hash,
    // enforced by the type signature above
    return keccak256(abi.encodePacked(
      "\x19Ethereum Signed Message:\n32",
      hash
    ));
  }
}

// File: contracts/MultiSigDocument.sol

contract ILockableStorage {
    function getAllKeys() public view returns(string);
    function addEntry(string memory key, string value) public;
    function getEntry(string memory key) public view returns (string);
    function updateEntry(string memory key, string value) public;
    function deleteEntry(string memory key) public; // Delete Value only
    function changeWritePermission(bool _writable, string memory key) public;

    event EntrySet(address indexed document, string entryKey);
    event EntryDeleted(address indexed document, string entryKey);
    event EntryUpdateRequest(address indexed document, string entryKey);
}

contract IMultipleSignatory {
    function isEnoughSignature() public view returns (bool);
    function changeNumberOfRquiredSignatures(uint newRequiredNumber) public;
    function isVerifier(address addr) public view returns (bool);
    function isIssuer(address addr) public view returns (bool);

    function signDocument(bytes memory sig) public;
    function verifyDocument() public;
    function revokeDocument() public;
    function deleteDocument() public;
    function submitDeleteConfirmation(bool deleted, bytes memory sig) public;
    function getProofHash() public view returns (bytes32);
    function isValidDataHash(bytes32 hash, bytes _sig) internal view returns(bool);
    function isVerified() public view returns (bool);

    event Verification(address indexed verifier, address indexed doc);
    event Revocation(address indexed verifier, address indexed doc);

    event LogInvalidSignatureSubmission(address submitter);
    event LogNumOfRequiredSignatureChanged(uint oldNum, uint indexed newNum);
    event DocumentSigned(address indexed document, address indexed verifier);
    event DeleteDocumentConfirmation(address indexed document, address indexed verifier);
}

contract MultiSigDocument is IMultipleSignatory {
  using ECRecovery for bytes32;
  uint public constant MAX_SIGNER_COUNT = 10;
  uint public createdTime; //Timestamp
  uint public validDays = 365; //days
  uint public expiration = 2**256-1; // Default to infinite time - Timestamp
  bool public autoActivation = false;
  bool public verified = false;
  uint public allowModificationDeadline = 0; //Timestamp
  uint public numOfRequiredSignature;

  address public verifier;
  address public issuer;
  // Keep track of signers
  // uint32 public signerCount = 0; // include issuer
  uint8 public finalizedSigConfirmations = 0;

  uint8 public deleteConfirmations = 0;

  mapping (address => SignerProperty) public signerProperties;

  address[] signers = new address[](MAX_SIGNER_COUNT);

  struct SignerProperty {
    bool IsSigner;
    bool IsSigned;
    bool DeleteConfirmed;
  }

  modifier validRequirement(uint _signerCount,
                            uint _numOfRequiredSignature,
                            uint _validDays,
                            uint _allowRevocationPeriodInDays)
  {
      require(_signerCount > 0 && _signerCount <= MAX_SIGNER_COUNT);
      require(_numOfRequiredSignature > 0  && _numOfRequiredSignature < MAX_SIGNER_COUNT);
      require(_validDays > 0 && _allowRevocationPeriodInDays < _validDays);
      _;
  }
  modifier signerDoesNotExist(address addr) {
      require(!signerProperties[addr].IsSigner);
      _;
  }
  // GDPR
  modifier allowDelete() {
      require(checkDeleteConfirmations());
      _;
  }

  modifier beforeModificationDeadline() {
      require(now < allowModificationDeadline);
      _;
  }

  modifier afterModificationDeadline() {
      require(now > allowModificationDeadline);
      _;
  }

  modifier signerExists(address addr) {
      require(signerProperties[addr].IsSigner);
      _;
  }

  modifier onlyVerifier() {
      require(verifier == msg.sender);
      _;
  }

  modifier isExpired() {
      require(now > expiration);
      _;
  }

  modifier onlyIssuer() {
      require(issuer == msg.sender);
      _;
  }
  modifier notVerified() {
      assert(!verified);
      _;
  }

  constructor(address[] _signer,
              address _verifier,
              uint _numOfRequiredSignature,
              uint _validDays,
              uint _allowRevocationPeriodInDays)
      public
      validRequirement(
        _signer.length,
        _numOfRequiredSignature,
        _validDays,
        _allowRevocationPeriodInDays)
  {
      for (uint i=0; i<_signer.length; i++) {
          assert(_signer[i] != address(0) && _signer[i] != msg.sender);
          signerProperties[_signer[i]].IsSigner = true;
          signers.push(_signer[i]);
      }
      issuer = msg.sender;
      signerProperties[issuer].IsSigner = true;

      signers.push(issuer);
      verifier = _verifier;

      createdTime = now;
      validDays = _validDays == 0 ? 0 : _validDays;
      expiration = _validDays == 0 ? expiration : (createdTime + (validDays * 1 days));
      numOfRequiredSignature = _numOfRequiredSignature + 1;
      allowModificationDeadline = createdTime + (_allowRevocationPeriodInDays * 1 days);
  }
  function isVerifier(address addr)
    public
    view
    returns (bool)
  {
    return (verifier == addr);
  }
  function isIssuer(address addr)
    public
    view
    returns (bool)
  {
    return (issuer == addr);
  }
  function submitDeleteConfirmation(bool confirmedDeleted, bytes memory sig)
      public
  {
      address recoveredAddr = keccak256(abi.encodePacked(address(this), confirmedDeleted))
        .toEthSignedMessageHash()
        .recover(sig);
      assert(signerProperties[recoveredAddr].IsSigner);
      assert(signerProperties[recoveredAddr].IsSigned);

      signerProperties[recoveredAddr].DeleteConfirmed = confirmedDeleted;
      emit DeleteDocumentConfirmation(address(this), verifier);
  }



  function changeNumberOfRquiredSignatures(uint newRequiredNumber)
      public
      onlyVerifier()
      beforeModificationDeadline()
      notVerified()
  {
      require(newRequiredNumber > 0  && newRequiredNumber < signers.length);
      emit LogNumOfRequiredSignatureChanged(numOfRequiredSignature, newRequiredNumber);
      numOfRequiredSignature = newRequiredNumber;
  }


  function signDocument(bytes  memory sig)
      public
      afterModificationDeadline()
  {
      if(!isValidSignature(sig)) {
        emit LogInvalidSignatureSubmission(msg.sender);
        revert('Submitting signature is invalid!');
      }
      address recoveredAddr = keccak256(
        abi.encodePacked(address(this), verifier, getProofHash()))
        .toEthSignedMessageHash()
        .recover(sig);
      signerProperties[recoveredAddr].IsSigned = true;
      finalizedSigConfirmations++;

      emit DocumentSigned(address(this), verifier);
  }

  /**
   * TODO: Overide this function
   */
  function getProofHash()
    public
    view
    returns (bytes32)
  {
    return keccak256(abi.encodePacked(""));
  }
  /**
   * @dev is the signature of `this + verifier + documentProofHash` from a signer?
   * @return bool
   */
  function isValidSignature(bytes _sig)
    internal
    view
    returns (bool)
  {
    return isValidDataHash(
      keccak256(abi.encodePacked(address(this), verifier, getProofHash())),
      _sig
    );
  }
  /**
   * @dev internal function to convert a hash to an eth signed message
   * and then recover the signature and check it against the bouncer role
   * @return bool
   */
  function isValidDataHash(bytes32 hash, bytes _sig)
    internal
    view
    returns (bool)
  {
    address recoveredAddr = hash
      .toEthSignedMessageHash()
      .recover(_sig);
    return signerProperties[recoveredAddr].IsSigner;
  }

  function isEnoughSignature()
      public
      view
      returns (bool)
  {

      if(!signerProperties[issuer].IsSigned) return false;
      if(finalizedSigConfirmations < numOfRequiredSignature) return false;
      return true;
  }

  function checkDeleteConfirmations()
      public
      view
      returns (bool)
  {
      uint8 _tmpCount = 0;
      for (uint8 i=0; i < signers.length; i++) {
          if (signerProperties[signers[i]].DeleteConfirmed == true)
            _tmpCount++;
      }
      if(_tmpCount < numOfRequiredSignature) {
          return false;

      }
      return true;
  }

  function verifyDocument()
      public
      notVerified()
      onlyVerifier()
      afterModificationDeadline()
  {
      /*
       * TODO: Please extend this function by adding validation of signature
       */
      assert(isEnoughSignature());
      verified = true;
      emit Verification(msg.sender, address(this));
  }

  function deleteDocument()
      public
      isExpired()
      allowDelete()
      signerExists(msg.sender)
  {
      /*
       * TODO: Please extend this function
       */
      selfdestruct(issuer);
  }
  function isVerified()
      public
      view
      returns (bool)
  {
      return verified;
  }

  function revokeDocument()
      public
      isExpired()
      onlyVerifier()
  {
      verified = false;
      emit Revocation(verifier, address(this));
  }
  function () public {
    //fallback
  }
}

// File: contracts/lib/strings.sol

/*
 * @title String & slice utility library for Solidity contracts.
 * @author Nick Johnson <arachnid@notdot.net>
 *
 * @dev Functionality in this library is largely implemented using an
 *      abstraction called a 'slice'. A slice represents a part of a string -
 *      anything from the entire string to a single character, or even no
 *      characters at all (a 0-length slice). Since a slice only has to specify
 *      an offset and a length, copying and manipulating slices is a lot less
 *      expensive than copying and manipulating the strings they reference.
 *
 *      To further reduce gas costs, most functions on slice that need to return
 *      a slice modify the original one instead of allocating a new one; for
 *      instance, `s.split(".")` will return the text up to the first '.',
 *      modifying s to only contain the remainder of the string after the '.'.
 *      In situations where you do not want to modify the original slice, you
 *      can make a copy first with `.copy()`, for example:
 *      `s.copy().split(".")`. Try and avoid using this idiom in loops; since
 *      Solidity has no memory management, it will result in allocating many
 *      short-lived slices that are later discarded.
 *
 *      Functions that return two slices come in two versions: a non-allocating
 *      version that takes the second slice as an argument, modifying it in
 *      place, and an allocating version that allocates and returns the second
 *      slice; see `nextRune` for example.
 *
 *      Functions that have to copy string data will return strings rather than
 *      slices; these can be cast back to slices for further processing if
 *      required.
 *
 *      For convenience, some functions are provided with non-modifying
 *      variants that create a new slice and return both; for instance,
 *      `s.splitNew('.')` leaves s unmodified, and returns two values
 *      corresponding to the left and right parts of the string.
 */

pragma solidity ^0.4.14;

library strings {
    struct slice {
        uint _len;
        uint _ptr;
    }

    function memcpy(uint dest, uint src, uint len) private pure {
        // Copy word-length chunks while possible
        for(; len >= 32; len -= 32) {
            assembly {
                mstore(dest, mload(src))
            }
            dest += 32;
            src += 32;
        }

        // Copy remaining bytes
        uint mask = 256 ** (32 - len) - 1;
        assembly {
            let srcpart := and(mload(src), not(mask))
            let destpart := and(mload(dest), mask)
            mstore(dest, or(destpart, srcpart))
        }
    }

    /*
     * @dev Returns a slice containing the entire string.
     * @param self The string to make a slice from.
     * @return A newly allocated slice containing the entire string.
     */
    function toSlice(string self) internal pure returns (slice) {
        uint ptr;
        assembly {
            ptr := add(self, 0x20)
        }
        return slice(bytes(self).length, ptr);
    }

    /*
     * @dev Returns the length of a null-terminated bytes32 string.
     * @param self The value to find the length of.
     * @return The length of the string, from 0 to 32.
     */
    function len(bytes32 self) internal pure returns (uint) {
        uint ret;
        if (self == 0)
            return 0;
        if (self & 0xffffffffffffffffffffffffffffffff == 0) {
            ret += 16;
            self = bytes32(uint(self) / 0x100000000000000000000000000000000);
        }
        if (self & 0xffffffffffffffff == 0) {
            ret += 8;
            self = bytes32(uint(self) / 0x10000000000000000);
        }
        if (self & 0xffffffff == 0) {
            ret += 4;
            self = bytes32(uint(self) / 0x100000000);
        }
        if (self & 0xffff == 0) {
            ret += 2;
            self = bytes32(uint(self) / 0x10000);
        }
        if (self & 0xff == 0) {
            ret += 1;
        }
        return 32 - ret;
    }

    /*
     * @dev Returns a slice containing the entire bytes32, interpreted as a
     *      null-terminated utf-8 string.
     * @param self The bytes32 value to convert to a slice.
     * @return A new slice containing the value of the input argument up to the
     *         first null.
     */
    function toSliceB32(bytes32 self) internal pure returns (slice ret) {
        // Allocate space for `self` in memory, copy it there, and point ret at it
        assembly {
            let ptr := mload(0x40)
            mstore(0x40, add(ptr, 0x20))
            mstore(ptr, self)
            mstore(add(ret, 0x20), ptr)
        }
        ret._len = len(self);
    }

    /*
     * @dev Returns a new slice containing the same data as the current slice.
     * @param self The slice to copy.
     * @return A new slice containing the same data as `self`.
     */
    function copy(slice self) internal pure returns (slice) {
        return slice(self._len, self._ptr);
    }

    /*
     * @dev Copies a slice to a new string.
     * @param self The slice to copy.
     * @return A newly allocated string containing the slice's text.
     */
    function toString(slice self) internal pure returns (string) {
        string memory ret = new string(self._len);
        uint retptr;
        assembly { retptr := add(ret, 32) }

        memcpy(retptr, self._ptr, self._len);
        return ret;
    }

    /*
     * @dev Returns the length in runes of the slice. Note that this operation
     *      takes time proportional to the length of the slice; avoid using it
     *      in loops, and call `slice.empty()` if you only need to know whether
     *      the slice is empty or not.
     * @param self The slice to operate on.
     * @return The length of the slice in runes.
     */
    function len(slice self) internal pure returns (uint l) {
        // Starting at ptr-31 means the LSB will be the byte we care about
        uint ptr = self._ptr - 31;
        uint end = ptr + self._len;
        for (l = 0; ptr < end; l++) {
            uint8 b;
            assembly { b := and(mload(ptr), 0xFF) }
            if (b < 0x80) {
                ptr += 1;
            } else if(b < 0xE0) {
                ptr += 2;
            } else if(b < 0xF0) {
                ptr += 3;
            } else if(b < 0xF8) {
                ptr += 4;
            } else if(b < 0xFC) {
                ptr += 5;
            } else {
                ptr += 6;
            }
        }
    }

    /*
     * @dev Returns true if the slice is empty (has a length of 0).
     * @param self The slice to operate on.
     * @return True if the slice is empty, False otherwise.
     */
    function empty(slice self) internal pure returns (bool) {
        return self._len == 0;
    }

    /*
     * @dev Returns a positive number if `other` comes lexicographically after
     *      `self`, a negative number if it comes before, or zero if the
     *      contents of the two slices are equal. Comparison is done per-rune,
     *      on unicode codepoints.
     * @param self The first slice to compare.
     * @param other The second slice to compare.
     * @return The result of the comparison.
     */
    function compare(slice self, slice other) internal pure returns (int) {
        uint shortest = self._len;
        if (other._len < self._len)
            shortest = other._len;

        uint selfptr = self._ptr;
        uint otherptr = other._ptr;
        for (uint idx = 0; idx < shortest; idx += 32) {
            uint a;
            uint b;
            assembly {
                a := mload(selfptr)
                b := mload(otherptr)
            }
            if (a != b) {
                // Mask out irrelevant bytes and check again
                uint256 mask = uint256(-1); // 0xffff...
                if(shortest < 32) {
                  mask = ~(2 ** (8 * (32 - shortest + idx)) - 1);
                }
                uint256 diff = (a & mask) - (b & mask);
                if (diff != 0)
                    return int(diff);
            }
            selfptr += 32;
            otherptr += 32;
        }
        return int(self._len) - int(other._len);
    }

    /*
     * @dev Returns true if the two slices contain the same text.
     * @param self The first slice to compare.
     * @param self The second slice to compare.
     * @return True if the slices are equal, false otherwise.
     */
    function equals(slice self, slice other) internal pure returns (bool) {
        return compare(self, other) == 0;
    }

    /*
     * @dev Extracts the first rune in the slice into `rune`, advancing the
     *      slice to point to the next rune and returning `self`.
     * @param self The slice to operate on.
     * @param rune The slice that will contain the first rune.
     * @return `rune`.
     */
    function nextRune(slice self, slice rune) internal pure returns (slice) {
        rune._ptr = self._ptr;

        if (self._len == 0) {
            rune._len = 0;
            return rune;
        }

        uint l;
        uint b;
        // Load the first byte of the rune into the LSBs of b
        assembly { b := and(mload(sub(mload(add(self, 32)), 31)), 0xFF) }
        if (b < 0x80) {
            l = 1;
        } else if(b < 0xE0) {
            l = 2;
        } else if(b < 0xF0) {
            l = 3;
        } else {
            l = 4;
        }

        // Check for truncated codepoints
        if (l > self._len) {
            rune._len = self._len;
            self._ptr += self._len;
            self._len = 0;
            return rune;
        }

        self._ptr += l;
        self._len -= l;
        rune._len = l;
        return rune;
    }

    /*
     * @dev Returns the first rune in the slice, advancing the slice to point
     *      to the next rune.
     * @param self The slice to operate on.
     * @return A slice containing only the first rune from `self`.
     */
    function nextRune(slice self) internal pure returns (slice ret) {
        nextRune(self, ret);
    }

    /*
     * @dev Returns the number of the first codepoint in the slice.
     * @param self The slice to operate on.
     * @return The number of the first codepoint in the slice.
     */
    function ord(slice self) internal pure returns (uint ret) {
        if (self._len == 0) {
            return 0;
        }

        uint word;
        uint length;
        uint divisor = 2 ** 248;

        // Load the rune into the MSBs of b
        assembly { word:= mload(mload(add(self, 32))) }
        uint b = word / divisor;
        if (b < 0x80) {
            ret = b;
            length = 1;
        } else if(b < 0xE0) {
            ret = b & 0x1F;
            length = 2;
        } else if(b < 0xF0) {
            ret = b & 0x0F;
            length = 3;
        } else {
            ret = b & 0x07;
            length = 4;
        }

        // Check for truncated codepoints
        if (length > self._len) {
            return 0;
        }

        for (uint i = 1; i < length; i++) {
            divisor = divisor / 256;
            b = (word / divisor) & 0xFF;
            if (b & 0xC0 != 0x80) {
                // Invalid UTF-8 sequence
                return 0;
            }
            ret = (ret * 64) | (b & 0x3F);
        }

        return ret;
    }

    /*
     * @dev Returns the keccak-256 hash of the slice.
     * @param self The slice to hash.
     * @return The hash of the slice.
     */
    function keccak(slice self) internal pure returns (bytes32 ret) {
        assembly {
            ret := keccak256(mload(add(self, 32)), mload(self))
        }
    }

    /*
     * @dev Returns true if `self` starts with `needle`.
     * @param self The slice to operate on.
     * @param needle The slice to search for.
     * @return True if the slice starts with the provided text, false otherwise.
     */
    function startsWith(slice self, slice needle) internal pure returns (bool) {
        if (self._len < needle._len) {
            return false;
        }

        if (self._ptr == needle._ptr) {
            return true;
        }

        bool equal;
        assembly {
            let length := mload(needle)
            let selfptr := mload(add(self, 0x20))
            let needleptr := mload(add(needle, 0x20))
            equal := eq(keccak256(selfptr, length), keccak256(needleptr, length))
        }
        return equal;
    }

    /*
     * @dev If `self` starts with `needle`, `needle` is removed from the
     *      beginning of `self`. Otherwise, `self` is unmodified.
     * @param self The slice to operate on.
     * @param needle The slice to search for.
     * @return `self`
     */
    function beyond(slice self, slice needle) internal pure returns (slice) {
        if (self._len < needle._len) {
            return self;
        }

        bool equal = true;
        if (self._ptr != needle._ptr) {
            assembly {
                let length := mload(needle)
                let selfptr := mload(add(self, 0x20))
                let needleptr := mload(add(needle, 0x20))
                equal := eq(sha3(selfptr, length), sha3(needleptr, length))
            }
        }

        if (equal) {
            self._len -= needle._len;
            self._ptr += needle._len;
        }

        return self;
    }

    /*
     * @dev Returns true if the slice ends with `needle`.
     * @param self The slice to operate on.
     * @param needle The slice to search for.
     * @return True if the slice starts with the provided text, false otherwise.
     */
    function endsWith(slice self, slice needle) internal pure returns (bool) {
        if (self._len < needle._len) {
            return false;
        }

        uint selfptr = self._ptr + self._len - needle._len;

        if (selfptr == needle._ptr) {
            return true;
        }

        bool equal;
        assembly {
            let length := mload(needle)
            let needleptr := mload(add(needle, 0x20))
            equal := eq(keccak256(selfptr, length), keccak256(needleptr, length))
        }

        return equal;
    }

    /*
     * @dev If `self` ends with `needle`, `needle` is removed from the
     *      end of `self`. Otherwise, `self` is unmodified.
     * @param self The slice to operate on.
     * @param needle The slice to search for.
     * @return `self`
     */
    function until(slice self, slice needle) internal pure returns (slice) {
        if (self._len < needle._len) {
            return self;
        }

        uint selfptr = self._ptr + self._len - needle._len;
        bool equal = true;
        if (selfptr != needle._ptr) {
            assembly {
                let length := mload(needle)
                let needleptr := mload(add(needle, 0x20))
                equal := eq(keccak256(selfptr, length), keccak256(needleptr, length))
            }
        }

        if (equal) {
            self._len -= needle._len;
        }

        return self;
    }

    event log_bytemask(bytes32 mask);

    // Returns the memory address of the first byte of the first occurrence of
    // `needle` in `self`, or the first byte after `self` if not found.
    function findPtr(uint selflen, uint selfptr, uint needlelen, uint needleptr) private pure returns (uint) {
        uint ptr = selfptr;
        uint idx;

        if (needlelen <= selflen) {
            if (needlelen <= 32) {
                bytes32 mask = bytes32(~(2 ** (8 * (32 - needlelen)) - 1));

                bytes32 needledata;
                assembly { needledata := and(mload(needleptr), mask) }

                uint end = selfptr + selflen - needlelen;
                bytes32 ptrdata;
                assembly { ptrdata := and(mload(ptr), mask) }

                while (ptrdata != needledata) {
                    if (ptr >= end)
                        return selfptr + selflen;
                    ptr++;
                    assembly { ptrdata := and(mload(ptr), mask) }
                }
                return ptr;
            } else {
                // For long needles, use hashing
                bytes32 hash;
                assembly { hash := sha3(needleptr, needlelen) }

                for (idx = 0; idx <= selflen - needlelen; idx++) {
                    bytes32 testHash;
                    assembly { testHash := sha3(ptr, needlelen) }
                    if (hash == testHash)
                        return ptr;
                    ptr += 1;
                }
            }
        }
        return selfptr + selflen;
    }

    // Returns the memory address of the first byte after the last occurrence of
    // `needle` in `self`, or the address of `self` if not found.
    function rfindPtr(uint selflen, uint selfptr, uint needlelen, uint needleptr) private pure returns (uint) {
        uint ptr;

        if (needlelen <= selflen) {
            if (needlelen <= 32) {
                bytes32 mask = bytes32(~(2 ** (8 * (32 - needlelen)) - 1));

                bytes32 needledata;
                assembly { needledata := and(mload(needleptr), mask) }

                ptr = selfptr + selflen - needlelen;
                bytes32 ptrdata;
                assembly { ptrdata := and(mload(ptr), mask) }

                while (ptrdata != needledata) {
                    if (ptr <= selfptr)
                        return selfptr;
                    ptr--;
                    assembly { ptrdata := and(mload(ptr), mask) }
                }
                return ptr + needlelen;
            } else {
                // For long needles, use hashing
                bytes32 hash;
                assembly { hash := sha3(needleptr, needlelen) }
                ptr = selfptr + (selflen - needlelen);
                while (ptr >= selfptr) {
                    bytes32 testHash;
                    assembly { testHash := sha3(ptr, needlelen) }
                    if (hash == testHash)
                        return ptr + needlelen;
                    ptr -= 1;
                }
            }
        }
        return selfptr;
    }

    /*
     * @dev Modifies `self` to contain everything from the first occurrence of
     *      `needle` to the end of the slice. `self` is set to the empty slice
     *      if `needle` is not found.
     * @param self The slice to search and modify.
     * @param needle The text to search for.
     * @return `self`.
     */
    function find(slice self, slice needle) internal pure returns (slice) {
        uint ptr = findPtr(self._len, self._ptr, needle._len, needle._ptr);
        self._len -= ptr - self._ptr;
        self._ptr = ptr;
        return self;
    }

    /*
     * @dev Modifies `self` to contain the part of the string from the start of
     *      `self` to the end of the first occurrence of `needle`. If `needle`
     *      is not found, `self` is set to the empty slice.
     * @param self The slice to search and modify.
     * @param needle The text to search for.
     * @return `self`.
     */
    function rfind(slice self, slice needle) internal pure returns (slice) {
        uint ptr = rfindPtr(self._len, self._ptr, needle._len, needle._ptr);
        self._len = ptr - self._ptr;
        return self;
    }

    /*
     * @dev Splits the slice, setting `self` to everything after the first
     *      occurrence of `needle`, and `token` to everything before it. If
     *      `needle` does not occur in `self`, `self` is set to the empty slice,
     *      and `token` is set to the entirety of `self`.
     * @param self The slice to split.
     * @param needle The text to search for in `self`.
     * @param token An output parameter to which the first token is written.
     * @return `token`.
     */
    function split(slice self, slice needle, slice token) internal pure returns (slice) {
        uint ptr = findPtr(self._len, self._ptr, needle._len, needle._ptr);
        token._ptr = self._ptr;
        token._len = ptr - self._ptr;
        if (ptr == self._ptr + self._len) {
            // Not found
            self._len = 0;
        } else {
            self._len -= token._len + needle._len;
            self._ptr = ptr + needle._len;
        }
        return token;
    }

    /*
     * @dev Splits the slice, setting `self` to everything after the first
     *      occurrence of `needle`, and returning everything before it. If
     *      `needle` does not occur in `self`, `self` is set to the empty slice,
     *      and the entirety of `self` is returned.
     * @param self The slice to split.
     * @param needle The text to search for in `self`.
     * @return The part of `self` up to the first occurrence of `delim`.
     */
    function split(slice self, slice needle) internal pure returns (slice token) {
        split(self, needle, token);
    }

    /*
     * @dev Splits the slice, setting `self` to everything before the last
     *      occurrence of `needle`, and `token` to everything after it. If
     *      `needle` does not occur in `self`, `self` is set to the empty slice,
     *      and `token` is set to the entirety of `self`.
     * @param self The slice to split.
     * @param needle The text to search for in `self`.
     * @param token An output parameter to which the first token is written.
     * @return `token`.
     */
    function rsplit(slice self, slice needle, slice token) internal pure returns (slice) {
        uint ptr = rfindPtr(self._len, self._ptr, needle._len, needle._ptr);
        token._ptr = ptr;
        token._len = self._len - (ptr - self._ptr);
        if (ptr == self._ptr) {
            // Not found
            self._len = 0;
        } else {
            self._len -= token._len + needle._len;
        }
        return token;
    }

    /*
     * @dev Splits the slice, setting `self` to everything before the last
     *      occurrence of `needle`, and returning everything after it. If
     *      `needle` does not occur in `self`, `self` is set to the empty slice,
     *      and the entirety of `self` is returned.
     * @param self The slice to split.
     * @param needle The text to search for in `self`.
     * @return The part of `self` after the last occurrence of `delim`.
     */
    function rsplit(slice self, slice needle) internal pure returns (slice token) {
        rsplit(self, needle, token);
    }

    /*
     * @dev Counts the number of nonoverlapping occurrences of `needle` in `self`.
     * @param self The slice to search.
     * @param needle The text to search for in `self`.
     * @return The number of occurrences of `needle` found in `self`.
     */
    function count(slice self, slice needle) internal pure returns (uint cnt) {
        uint ptr = findPtr(self._len, self._ptr, needle._len, needle._ptr) + needle._len;
        while (ptr <= self._ptr + self._len) {
            cnt++;
            ptr = findPtr(self._len - (ptr - self._ptr), ptr, needle._len, needle._ptr) + needle._len;
        }
    }

    /*
     * @dev Returns True if `self` contains `needle`.
     * @param self The slice to search.
     * @param needle The text to search for in `self`.
     * @return True if `needle` is found in `self`, false otherwise.
     */
    function contains(slice self, slice needle) internal pure returns (bool) {
        return rfindPtr(self._len, self._ptr, needle._len, needle._ptr) != self._ptr;
    }

    /*
     * @dev Returns a newly allocated string containing the concatenation of
     *      `self` and `other`.
     * @param self The first slice to concatenate.
     * @param other The second slice to concatenate.
     * @return The concatenation of the two strings.
     */
    function concat(slice self, slice other) internal pure returns (string) {
        string memory ret = new string(self._len + other._len);
        uint retptr;
        assembly { retptr := add(ret, 32) }
        memcpy(retptr, self._ptr, self._len);
        memcpy(retptr + self._len, other._ptr, other._len);
        return ret;
    }

    /*
     * @dev Joins an array of slices, using `self` as a delimiter, returning a
     *      newly allocated string.
     * @param self The delimiter to use.
     * @param parts A list of slices to join.
     * @return A newly allocated string containing all the slices in `parts`,
     *         joined with `self`.
     */
    function join(slice self, slice[] parts) internal pure returns (string) {
        if (parts.length == 0)
            return "";

        uint length = self._len * (parts.length - 1);
        for(uint i = 0; i < parts.length; i++)
            length += parts[i]._len;

        string memory ret = new string(length);
        uint retptr;
        assembly { retptr := add(ret, 32) }

        for(i = 0; i < parts.length; i++) {
            memcpy(retptr, parts[i]._ptr, parts[i]._len);
            retptr += parts[i]._len;
            if (i < parts.length - 1) {
                memcpy(retptr, self._ptr, self._len);
                retptr += self._len;
            }
        }

        return ret;
    }
}

// File: contracts/MultiSigDocumentWithStorage.sol

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

// File: contracts/MultiSigDocumentRegistry.sol

contract MultiSigDocumentRegistry {
  using strings for *;

  event DocumentIndexed(address indexed issuer, address indexed docAddr);
  event DocumentCreated(address indexed issuer, address indexed docAddr);
  event VerifierRegistration(address indexed issuer);

  struct Verifier {
      bool isVerifier;
      string Name;
      string Email;
  }
  //Store verifier info.
  mapping (address => Verifier) public verifierInfo;
  // Store created and indexed Document by Issuer's address
  mapping (address => mapping(uint => MultiSigDocumentWithStorage)) public docVault;
  // Keep track how many documents each Issuer have.
  mapping (address => uint) docCount;

  modifier onlyVerifier(bool isVerifier) {
      assert(isVerifier);
      _;
  }
  modifier onlyIssuer(bool isIssuer) {
      assert(isIssuer);
      _;
  }
  modifier isRegisteredVerifier(address a1) {
      assert(verifierInfo[a1].isVerifier);
      _;
  }

  constructor()
    public
  {

  }
  modifier stringNotEmpty(string memory s1) {
    assert(bytes(s1).length != 0);
    _;
  }
  function registerVerifier(string memory _name, string memory _email)
    public
    stringNotEmpty(_name)
    stringNotEmpty(_email)
  {
    verifierInfo[msg.sender] = Verifier({
        isVerifier: true,
        Name: _name,
        Email: _email
      });
    emit VerifierRegistration(msg.sender);
  }

  function createDocument(
    address[] signers,
    address verifier,
    uint8 required,
    uint validDays,
    uint offset,
    bytes buffer
  )
    public
    isRegisteredVerifier(verifier)
    returns (address)
  {
    docVault[msg.sender][docCount[msg.sender]] =
      new MultiSigDocumentWithStorage(signers, verifier, required, validDays, offset, buffer);

    docCount[msg.sender] = docCount[msg.sender] + 1;

    emit DocumentCreated(msg.sender, address(docVault[msg.sender][docCount[msg.sender]]));
    return docVault[msg.sender][docCount[msg.sender]];
  }

  function setDocument(MultiSigDocumentWithStorage doc)
    public
    onlyIssuer(doc.isIssuer(msg.sender))
  {
    /* docVault[msg.sender][docCount[msg.sender]] = Document({docAddr: docAddr}); */
    docVault[msg.sender][docCount[msg.sender]] = doc;

    docCount[msg.sender] = docCount[msg.sender] + 1;

    emit DocumentIndexed(msg.sender, address(doc));
  }

  function isVerified(address addr, uint docId)
    public
    view
    returns (bool)
  {
    return docVault[addr][docId].isVerified();
  }

  function getEntry(address issuer, uint docId, string memory key)
    public
    view
    returns (string)
  {
    return docVault[issuer][docId].getEntry(key);
  }

  function getProofHash(address issuer, uint docId)
    public
    view
    returns (bytes32)
  {
    return docVault[issuer][docId].getProofHash();
  }




}
