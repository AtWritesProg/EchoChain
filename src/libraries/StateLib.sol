//SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

/**
 * @title StateLib
 * @notice Library for state machine management
 */
library StateLib {
    enum State {
        Setup,
        Active,
        Warning,
        Triggered,
        Distributing,
        Distributed,
        Cancelled
    }

    struct StateMeta {
        State current;
        uint32 enteredAt;
        uint32 transitionCount;
        State previous;
    }

    /**
     * @notice Check if state transition is valid
     */
    function isValidTransition(
        State from,
        State to
    ) internal pure returns (bool) {
        if (from == State.Setup) {
            return to == State.Active || to == State.Cancelled;
        }
        if (from == State.Active) {
            return to == State.Warning || to == State.Cancelled;
        }
        if (from == State.Warning) {
            return
                to == State.Active ||
                to == State.Triggered ||
                to == State.Cancelled;
        }
        if (from == State.Triggered) {
            return
                to == State.Distributing ||
                to == State.Active ||
                to == State.Cancelled;
        }
        if (from == State.Distributing) {
            return to == State.Distributed;
        }
        // Terminal states: Distributed and Cancelled
        return false;
    }

    /**
     * @notice Convert state enum to string
     */
    function toString(State state) internal pure returns (string memory) {
        if (state == State.Setup) return "Setup";
        if (state == State.Active) return "Active";
        if (state == State.Warning) return "Warning";
        if (state == State.Triggered) return "Triggered";
        if (state == State.Distributing) return "Distributing";
        if (state == State.Distributed) return "Distributed";
        if (state == State.Cancelled) return "Cancelled";
        return "Unknown";
    }
}
