// guard.sol -- simple auth implementation

// Copyright (C) 2019 Maker Ecosystem Growth Holdings, INC.
//
// Original DS-Guard Implementation:
// source: https://github.com/dapphub/ds-guard
// Copyright (C) 2017 DappHub, LLC

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

pragma solidity >=0.5.0;

contract DSGuard {
    address public owner;
    mapping (address => mapping (address => mapping (bytes32 => bool))) acl;

    event LogSetOwner (address indexed owner);

    event LogPermit(
        address indexed src,
        address indexed dst,
        bytes32 indexed sig
    );

    event LogForbid(
        address indexed src,
        address indexed dst,
        bytes32 indexed sig
    );

    constructor() public {
        owner = msg.sender;
        emit LogSetOwner(msg.sender);
    }

    modifier auth {
        require(msg.sender == owner, "dss-guard-unauthorized");
        _;
    }

    function canCall(
        address src, address dst, bytes4 sig
    ) public view returns (bool) {
        return acl[src][dst][sig];
    }

    function setOwner(address owner_)
        public
        auth
    {
        owner = owner_;
        emit LogSetOwner(owner);
    }

    function forbid(address src, address dst, bytes32 sig) public auth {
        acl[src][dst][sig] = false;
        emit LogForbid(src, dst, sig);
    }

    function permit(address src, address dst, bytes32 sig) public auth {
        acl[src][dst][sig] = true;
        emit LogPermit(src, dst, sig);
    }
}
