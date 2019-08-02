// guard.t.sol -- tests for guard.sol

// Copyright (C) 2019 Maker Ecosystem Growth Holdings, INC.
//
// Original DS-Guard Implementation:
// source: https://github.com/dapphub/ds-guard
// Copyright (C) 2017 DappHub, LLCC

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

pragma solidity >=0.4.23;

import "ds-test/test.sol";

import "./guard.sol";

contract FakeGuard is DSGuard {
    function access() public view auth {}
}

contract DSGuardTest is DSTest, DSGuard {
    FakeGuard guard;
    bytes4 sig = bytes4(keccak256("test()"));

    function setUp() public {
        guard = new FakeGuard();
    }

    function test_owner() public {
        guard.setOwner(address(0));
    }

    function testFail_non_owner_1() public {
        guard.setOwner(address(0));
        guard.access();
    }

    function testFail_non_owner_2() public {
        guard.setOwner(address(0));
        guard.setOwner(address(0));
    }

    function testPermitAddress() public {
        guard.permit(address(this), address(0x1234), sig);
        assertTrue(guard.canCall(address(this), address(0x1234), sig));
        assertTrue(!guard.canCall(address(this), address(0x5678), sig));
    }

    function testForbidAddress() public {
        guard.permit(address(this), address(0x1234), sig);
        assertTrue(guard.canCall(address(this), address(0x1234), sig));
        guard.forbid(address(this), address(0x1234), sig);
        assertTrue(!guard.canCall(address(this), address(0x1234), sig));
    }
}
