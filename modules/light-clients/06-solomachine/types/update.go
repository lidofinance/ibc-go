package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	clienttypes "github.com/cosmos/ibc-go/v3/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/v3/modules/core/exported"
)

// CheckHeaderAndUpdateState checks if the provided header is valid and updates
// the consensus state if appropriate. It returns an error if:
// - the header provided is not parseable to a solo machine header
// - the header sequence does not match the current sequence
// - the header timestamp is less than the consensus state timestamp
// - the currently registered public key did not provide the update signature
func (cs ClientState) CheckHeaderAndUpdateState(
	ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore,
	header exported.Header,
) (exported.ClientState, exported.ConsensusState, error) {
	if err := cs.VerifyHeader(cdc, header); err != nil {
		return nil, nil, err
	}

	// TODO: #878 - Remove in PR 3 when changing: update -> UpdateState
	if h, ok := header.(*Header); ok {
		clientState, consensusState := update(&cs, h)
		return clientState, consensusState, nil
	}

	return nil, nil, nil
}

// VerifyHeader checks if the Solo Machine update signature is valid.
func (cs ClientState) VerifyHeader(cdc codec.BinaryCodec, header exported.Header) error {
	switch header := header.(type) {
	case *Header:
		// assert update sequence is current sequence
		if header.Sequence != cs.Sequence {
			return sdkerrors.Wrapf(
				clienttypes.ErrInvalidHeader,
				"header sequence does not match the client state sequence (%d != %d)", header.Sequence, cs.Sequence,
			)
		}

		// assert update timestamp is not less than current consensus state timestamp
		if header.Timestamp < cs.ConsensusState.Timestamp {
			return sdkerrors.Wrapf(
				clienttypes.ErrInvalidHeader,
				"header timestamp is less than to the consensus state timestamp (%d < %d)", header.Timestamp, cs.ConsensusState.Timestamp,
			)
		}

		// assert currently registered public key signed over the new public key with correct sequence
		data, err := HeaderSignBytes(cdc, header)
		if err != nil {
			return err
		}

		sigData, err := UnmarshalSignatureData(cdc, header.Signature)
		if err != nil {
			return err
		}

		publicKey, err := cs.ConsensusState.GetPubKey()
		if err != nil {
			return err
		}

		if err := VerifySignature(publicKey, data, sigData); err != nil {
			return sdkerrors.Wrap(ErrInvalidHeader, err.Error())
		}
	case *DuplicateSignatures:
		// verify first signature
		if err := verifySignatureAndData(cdc, cs, header, header.SignatureOne); err != nil {
			return sdkerrors.Wrap(err, "failed to verify signature one")
		}

		// verify second signature
		if err := verifySignatureAndData(cdc, cs, header, header.SignatureTwo); err != nil {
			return sdkerrors.Wrap(err, "failed to verify signature two")
		}
	default:
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "unexpected type for header: %s", header)
	}

	return nil
}

// update the consensus state to the new public key and an incremented sequence
func update(clientState *ClientState, header *Header) (*ClientState, *ConsensusState) {
	consensusState := &ConsensusState{
		PublicKey:   header.NewPublicKey,
		Diversifier: header.NewDiversifier,
		Timestamp:   header.Timestamp,
	}

	// increment sequence number
	clientState.Sequence++
	clientState.ConsensusState = consensusState
	return clientState, consensusState
}
