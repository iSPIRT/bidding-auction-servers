#!/usr/bin/env python3
"""Test protobuf conversion functionality."""

import sys
import json
from google.protobuf import json_format


def test_json_to_proto_basic():
    """Test basic JSON to protobuf conversion."""
    print("\n1. Testing basic JSON to Proto conversion...")
    
    try:
        from secure_invoke.protos import bidding_auction_servers_pb2
        
        # Create a simple request
        json_request = {
            "seller": "example.com",
            "publisherName": "publisher.com",
            "auctionSignals": "{}",
            "buyerSignals": "{}"
        }
        
        # Convert to proto
        proto_request = bidding_auction_servers_pb2.GetBidsRequest.GetBidsRawRequest()
        json_format.ParseDict(json_request, proto_request)
        
        # Verify fields
        assert proto_request.seller == "example.com", "Seller mismatch"
        assert proto_request.publisher_name == "publisher.com", "Publisher name mismatch"
        assert proto_request.auction_signals == "{}", "Auction signals mismatch"
        
        print("✓ Basic JSON to Proto conversion successful")
        return True
    except Exception as e:
        print(f"✗ Basic JSON to Proto conversion failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_nested_structures():
    """Test conversion with nested structures."""
    print("\n2. Testing nested structure conversion...")
    
    try:
        from secure_invoke.protos import bidding_auction_servers_pb2
        
        # Create request with nested buyer input
        json_request = {
            "seller": "example.com",
            "publisherName": "publisher.com",
            "buyerInput": {
                "interestGroups": [
                    {
                        "name": "Test Group 1",
                        "biddingSignalsKeys": ["key1", "key2"],
                        "userBiddingSignals": '{"age": 25}',
                        "adRenderIds": ["ad1", "ad2"]
                    },
                    {
                        "name": "Test Group 2",
                        "biddingSignalsKeys": ["key3"],
                        "userBiddingSignals": '{"interests": ["sports"]}',
                        "browserSignals": {
                            "joinCount": 5,
                            "bidCount": 3,
                            "prevWins": "[]"
                        }
                    }
                ]
            }
        }
        
        # Convert to proto
        proto_request = bidding_auction_servers_pb2.GetBidsRequest.GetBidsRawRequest()
        json_format.ParseDict(json_request, proto_request)
        
        # Verify nested structures
        assert len(proto_request.buyer_input.interest_groups) == 2, "Interest groups count mismatch"
        assert proto_request.buyer_input.interest_groups[0].name == "Test Group 1", "First group name mismatch"
        assert len(proto_request.buyer_input.interest_groups[0].bidding_signals_keys) == 2, "Keys count mismatch"
        assert proto_request.buyer_input.interest_groups[1].browser_signals.join_count == 5, "Browser signals mismatch"
        
        print("✓ Nested structure conversion successful")
        return True
    except Exception as e:
        print(f"✗ Nested structure conversion failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_serialization_deserialization():
    """Test protobuf serialization and deserialization."""
    print("\n3. Testing Proto serialization/deserialization...")
    
    try:
        from secure_invoke.protos import bidding_auction_servers_pb2
        
        # Create and populate proto
        proto1 = bidding_auction_servers_pb2.GetBidsRequest.GetBidsRawRequest()
        proto1.seller = "example.com"
        proto1.publisher_name = "publisher.com"
        proto1.auction_signals = '{"test": "value"}'
        
        # Add interest group
        ig = proto1.buyer_input.interest_groups.add()
        ig.name = "Test Group"
        ig.bidding_signals_keys.extend(["key1", "key2"])
        ig.user_bidding_signals = '{"age": 30}'
        
        # Serialize to bytes
        serialized = proto1.SerializeToString()
        print(f"  Serialized size: {len(serialized)} bytes")
        
        # Deserialize back
        proto2 = bidding_auction_servers_pb2.GetBidsRequest.GetBidsRawRequest()
        proto2.ParseFromString(serialized)
        
        # Verify fields match
        assert proto2.seller == proto1.seller, "Seller mismatch after deserialization"
        assert proto2.publisher_name == proto1.publisher_name, "Publisher mismatch"
        assert len(proto2.buyer_input.interest_groups) == 1, "Interest groups lost"
        assert proto2.buyer_input.interest_groups[0].name == "Test Group", "Interest group name mismatch"
        assert len(proto2.buyer_input.interest_groups[0].bidding_signals_keys) == 2, "Keys lost"
        
        print("✓ Serialization/deserialization successful")
        return True
    except Exception as e:
        print(f"✗ Serialization/deserialization failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_proto_to_json():
    """Test protobuf to JSON conversion."""
    print("\n4. Testing Proto to JSON conversion...")
    
    try:
        from secure_invoke.protos import bidding_auction_servers_pb2
        
        # Create and populate proto
        proto = bidding_auction_servers_pb2.GetBidsRequest.GetBidsRawRequest()
        proto.seller = "example.com"
        proto.publisher_name = "publisher.com"
        proto.enable_debug_reporting = True
        
        ig = proto.buyer_input.interest_groups.add()
        ig.name = "Test Group"
        ig.bidding_signals_keys.extend(["key1", "key2"])
        
        # Convert to JSON
        json_str = json_format.MessageToJson(proto)
        json_dict = json.loads(json_str)
        
        # Verify JSON structure
        assert json_dict["seller"] == "example.com", "Seller in JSON mismatch"
        assert json_dict["publisherName"] == "publisher.com", "Publisher in JSON mismatch"
        assert json_dict["enableDebugReporting"] == True, "Debug flag mismatch"
        assert len(json_dict["buyerInput"]["interestGroups"]) == 1, "Interest groups in JSON mismatch"
        
        print("✓ Proto to JSON conversion successful")
        print(f"  JSON output: {json_str[:100]}...")
        return True
    except Exception as e:
        print(f"✗ Proto to JSON conversion failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_round_trip_conversion():
    """Test complete round-trip: JSON -> Proto -> Bytes -> Proto -> JSON."""
    print("\n5. Testing round-trip conversion...")
    
    try:
        from secure_invoke.protos import bidding_auction_servers_pb2
        
        # Original JSON
        original_json = {
            "clientType": "CLIENT_TYPE_BROWSER",
            "seller": "example.com",
            "publisherName": "publisher.com",
            "auctionSignals": '{"signal": "value"}',
            "buyerSignals": '{"buyer": "data"}',
            "enableDebugReporting": True,
            "buyerInput": {
                "interestGroups": [
                    {
                        "name": "Group1",
                        "biddingSignalsKeys": ["k1", "k2"],
                        "userBiddingSignals": '{"age": 25}',
                        "adRenderIds": ["ad1"]
                    }
                ]
            }
        }
        
        # Step 1: JSON -> Proto
        proto1 = bidding_auction_servers_pb2.GetBidsRequest.GetBidsRawRequest()
        json_format.ParseDict(original_json, proto1)
        
        # Step 2: Proto -> Bytes
        serialized = proto1.SerializeToString()
        
        # Step 3: Bytes -> Proto
        proto2 = bidding_auction_servers_pb2.GetBidsRequest.GetBidsRawRequest()
        proto2.ParseFromString(serialized)
        
        # Step 4: Proto -> JSON
        final_json_str = json_format.MessageToJson(proto2)
        final_json = json.loads(final_json_str)
        
        # Verify key fields match
        assert final_json["seller"] == original_json["seller"], "Seller mismatch in round-trip"
        assert final_json["publisherName"] == original_json["publisherName"], "Publisher mismatch"
        assert final_json["enableDebugReporting"] == True, "Debug flag lost"
        assert final_json["clientType"] == original_json["clientType"], "Client type mismatch"
        
        # Verify nested data
        assert len(final_json["buyerInput"]["interestGroups"]) == 1, "Interest groups lost in round-trip"
        assert final_json["buyerInput"]["interestGroups"][0]["name"] == "Group1", "Group name mismatch"
        
        print("✓ Round-trip conversion successful")
        print(f"  Original: {json.dumps(original_json, indent=2)[:150]}...")
        print(f"  Final:    {final_json_str[:150]}...")
        return True
    except Exception as e:
        print(f"✗ Round-trip conversion failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_client_type_enum():
    """Test ClientType enum handling."""
    print("\n6. Testing ClientType enum...")
    
    try:
        from secure_invoke.protos import bidding_auction_servers_pb2
        
        # Test different client types
        test_cases = [
            ("CLIENT_TYPE_BROWSER", bidding_auction_servers_pb2.CLIENT_TYPE_BROWSER),
            ("CLIENT_TYPE_ANDROID", bidding_auction_servers_pb2.CLIENT_TYPE_ANDROID),
        ]
        
        for json_value, enum_value in test_cases:
            proto = bidding_auction_servers_pb2.GetBidsRequest.GetBidsRawRequest()
            json_format.ParseDict({"clientType": json_value}, proto)
            assert proto.client_type == enum_value, f"Enum mismatch for {json_value}"
            print(f"  ✓ {json_value} -> {enum_value}")
        
        print("✓ ClientType enum handling successful")
        return True
    except Exception as e:
        print(f"✗ ClientType enum test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_log_context():
    """Test LogContext message handling."""
    print("\n7. Testing LogContext message...")
    
    try:
        from secure_invoke.protos import bidding_auction_servers_pb2
        
        json_request = {
            "seller": "example.com",
            "publisherName": "publisher.com",
            "logContext": {
                "generationId": "uuid-12345",
                "adtechDebugId": "debug-67890"
            }
        }
        
        proto = bidding_auction_servers_pb2.GetBidsRequest.GetBidsRawRequest()
        json_format.ParseDict(json_request, proto)
        
        assert proto.log_context.generation_id == "uuid-12345", "Generation ID mismatch"
        assert proto.log_context.adtech_debug_id == "debug-67890", "Debug ID mismatch"
        
        print("✓ LogContext message handling successful")
        return True
    except Exception as e:
        print(f"✗ LogContext test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_response_conversion():
    """Test GetBidsResponse conversion."""
    print("\n8. Testing GetBidsResponse conversion...")
    
    try:
        from secure_invoke.protos import bidding_auction_servers_pb2
        
        # Create response proto
        response = bidding_auction_servers_pb2.GetBidsResponse.GetBidsRawResponse()
        
        # Add a bid
        bid = response.bids.add()
        bid.ad_metadata = '{"advertiser": "test"}'
        bid.bid = 1.5
        bid.render = "https://example.com/ad"
        bid.bid_currency = "USD"
        
        # Add scoring signals
        response.ad_scoring_signals["key1"] = "value1"
        response.ad_scoring_signals["key2"] = "value2"
        
        # Convert to JSON
        json_str = json_format.MessageToJson(response)
        json_dict = json.loads(json_str)
        
        # Verify
        assert len(json_dict["bids"]) == 1, "Bids count mismatch"
        assert json_dict["bids"][0]["bid"] == 1.5, "Bid value mismatch"
        assert json_dict["bids"][0]["bidCurrency"] == "USD", "Currency mismatch"
        assert "adScoringSignals" in json_dict, "Scoring signals missing"
        
        print("✓ GetBidsResponse conversion successful")
        return True
    except Exception as e:
        print(f"✗ GetBidsResponse test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_real_world_request():
    """Test with a real-world request example."""
    print("\n9. Testing real-world request example...")
    
    try:
        from secure_invoke.protos import bidding_auction_servers_pb2
        
        # Real-world example from the spec
        json_request = {
            "clientType": "CLIENT_TYPE_BROWSER",
            "buyerInput": {
                "interestGroups": [
                    {
                        "name": "Rajni Kausalya",
                        "biddingSignalsKeys": ["9999999990"],
                        "userBiddingSignals": '{"age":29, "average_amount":10000}'
                    }
                ]
            },
            "seller": "irctc.com",
            "publisherName": "irctc.com"
        }
        
        # Convert to proto
        proto = bidding_auction_servers_pb2.GetBidsRequest.GetBidsRawRequest()
        json_format.ParseDict(json_request, proto)
        
        # Serialize
        serialized = proto.SerializeToString()
        print(f"  Serialized size: {len(serialized)} bytes")
        
        # Deserialize
        proto2 = bidding_auction_servers_pb2.GetBidsRequest.GetBidsRawRequest()
        proto2.ParseFromString(serialized)
        
        # Verify
        assert proto2.seller == "irctc.com", "Seller mismatch"
        assert proto2.publisher_name == "irctc.com", "Publisher mismatch"
        assert len(proto2.buyer_input.interest_groups) == 1, "Interest groups lost"
        assert proto2.buyer_input.interest_groups[0].name == "Rajni Kausalya", "Name mismatch"
        assert proto2.buyer_input.interest_groups[0].bidding_signals_keys[0] == "9999999990", "Key mismatch"
        
        # Convert back to JSON
        final_json = json_format.MessageToJson(proto2)
        print(f"  Round-trip successful: {len(final_json)} chars")
        
        print("✓ Real-world request handling successful")
        return True
    except Exception as e:
        print(f"✗ Real-world request test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_field_name_mapping():
    """Test snake_case to camelCase field name mapping."""
    print("\n10. Testing field name mapping...")
    
    try:
        from secure_invoke.protos import bidding_auction_servers_pb2
        
        # JSON uses camelCase
        json_request = {
            "publisherName": "test.com",  # camelCase
            "enableDebugReporting": True,  # camelCase
            "enableUnlimitedEgress": True,  # camelCase
        }
        
        # Proto uses snake_case
        proto = bidding_auction_servers_pb2.GetBidsRequest.GetBidsRawRequest()
        json_format.ParseDict(json_request, proto)
        
        # Verify snake_case fields are populated
        assert proto.publisher_name == "test.com", "publisher_name not mapped"
        assert proto.enable_debug_reporting == True, "enable_debug_reporting not mapped"
        assert proto.enable_unlimited_egress == True, "enable_unlimited_egress not mapped"
        
        # Convert back to JSON (should be camelCase)
        json_str = json_format.MessageToJson(proto)
        json_dict = json.loads(json_str)
        
        assert "publisherName" in json_dict, "camelCase not preserved in output"
        assert "enableDebugReporting" in json_dict, "camelCase not preserved"
        
        print("✓ Field name mapping successful")
        return True
    except Exception as e:
        print(f"✗ Field name mapping test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all protobuf conversion tests."""
    print("="*70)
    print("Testing Protobuf Conversion")
    print("="*70)
    
    tests = [
        ("Basic JSON to Proto", test_json_to_proto_basic),
        ("Nested Structures", test_nested_structures),
        ("Serialization/Deserialization", test_serialization_deserialization),
        ("Proto to JSON", test_proto_to_json),
        ("Round-trip Conversion", test_round_trip_conversion),
        ("ClientType Enum", test_client_type_enum),
        ("LogContext Message", test_log_context),
        ("GetBidsResponse", test_response_conversion),
        ("Real-world Request", test_real_world_request),
        ("Field Name Mapping", test_field_name_mapping),
    ]
    
    results = []
    for name, test_func in tests:
        result = test_func()
        results.append((name, result))
    
    # Summary
    print("\n" + "="*70)
    print("Test Summary")
    print("="*70)
    
    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{name:40s} {status}")
    
    print("="*70)
    total = len(results)
    passed = sum(1 for _, p in results if p)
    
    print(f"Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All protobuf conversion tests passed!")
        return 0
    else:
        print(f"\n❌ {total - passed} test(s) failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())

