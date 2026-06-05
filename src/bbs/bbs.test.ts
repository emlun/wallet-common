import { assert, describe, it } from "vitest";

import { concat, fromHex, toHex, toU8, toUtf8 } from "../utils/util";
import { asyncAssertThrows } from "../testutil";
import { getCipherSuite, PointG1 } from ".";


describe("Suite:", () => {

	const suiteId = 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_';

	describe(suiteId, () => {

		const suite = getCipherSuite(suiteId);
		const {
			Bbs,
			KeyGen,
			SkToPk,
			create_generators,
			hash_to_scalar,
			messages_to_scalars,
		} = suite;

		/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-messages-2 */
		const messages = [
			"9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
			"c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
			"7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
			"77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
			"496694774c5604ab1b2544eababcf0f53278ff50",
			"515ae153e22aae04ad16f759e07237b4",
			"d183ddc6e2665aa4e2f088af",
			"ac55fb33a75909ed",
			"96012096",
			"",
		].map(fromHex);

		describe("hash_to_scalar", () => {
			it("passes test vectors", async () => {
				// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-hash-to-scalar-test-vectors-2
				const msg = fromHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
				const dst = fromHex("4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4832535f");
				const scalar = await hash_to_scalar(msg, dst);
				assert.equal(scalar, 0x0f90cbee27beb214e6545becb8404640d3612da5d6758dffeccd77ed7169807cn);
			});
		});

		describe("keyGen", () => {
			it("passes test vectors", async () => {
				// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-key-pair-2
				const key_material = fromHex("746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579");
				const key_info = fromHex("746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e");
				const key_dst = concat(Bbs.api_id, toUtf8("KEYGEN_DST_"));
				const SK = await KeyGen(key_material, key_info, key_dst);
				const PK = SkToPk(SK);

				assert.equal(SK, 0x60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fcn);
				assert.equal(
					toHex(PK),
					"a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268" +
					"061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
				);
			});
		});

		describe("messages_to_scalars", () => {
			it("passes test vectors", async () => {
				// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-map-messages-to-scalars-2
				const scalars = await messages_to_scalars(messages, Bbs.api_id);

				assert.equal(scalars.length, 10);
				// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-messages-2
				assert.equal(scalars[0], 0x1cb5bb86114b34dc438a911617655a1db595abafac92f47c5001799cf624b430n);
				assert.equal(scalars[1], 0x154249d503c093ac2df516d4bb88b510d54fd97e8d7121aede420a25d9521952n);
				assert.equal(scalars[2], 0x0c7c4c85cdab32e6fdb0de267b16fa3212733d4e3a3f0d0f751657578b26fe22n);
				assert.equal(scalars[3], 0x4a196deafee5c23f630156ae13be3e46e53b7e39094d22877b8cba7f14640888n);
				assert.equal(scalars[4], 0x34c5ea4f2ba49117015a02c711bb173c11b06b3f1571b88a2952b93d0ed4cf7en);
				assert.equal(scalars[5], 0x4045b39b83055cd57a4d0203e1660800fabe434004dbdc8730c21ce3f0048b08n);
				assert.equal(scalars[6], 0x064621da4377b6b1d05ecc37cf3b9dfc94b9498d7013dc5c4a82bf3bb1750743n);
				assert.equal(scalars[7], 0x34ac9196ace0a37e147e32319ea9b3d8cc7d21870d3c3ba071246859cca49b02n);
				assert.equal(scalars[8], 0x57eb93f417c43200e9784fa5ea5a59168d3dbc38df707a13bb597c871b2a5f74n);
				assert.equal(scalars[9], 0x08e3afeb2b4f2b5f907924ef42856616e6f2d5f1fb373736db1cca32707a7d16n);
			});
		});

		describe("create_generators", () => {
			it("passes test vectors", async () => {
				// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-message-generators-2
				const count = 11;
				const generators = await create_generators(count, Bbs.api_id);

				assert.equal(generators.length, count);
				assert.equal(toHex(generators[0].toBytes()), "a9ec65b70a7fbe40c874c9eb041c2cb0a7af36ccec1bea48fa2ba4c2eb67ef7f9ecb17ed27d38d27cdeddff44c8137be");
				assert.equal(toHex(generators[1].toBytes()), "98cd5313283aaf5db1b3ba8611fe6070d19e605de4078c38df36019fbaad0bd28dd090fd24ed27f7f4d22d5ff5dea7d4");
				assert.equal(toHex(generators[2].toBytes()), "a31fbe20c5c135bcaa8d9fc4e4ac665cc6db0226f35e737507e803044093f37697a9d452490a970eea6f9ad6c3dcaa3a");
				assert.equal(toHex(generators[3].toBytes()), "b479263445f4d2108965a9086f9d1fdc8cde77d14a91c856769521ad3344754cc5ce90d9bc4c696dffbc9ef1d6ad1b62");
				assert.equal(toHex(generators[4].toBytes()), "ac0401766d2128d4791d922557c7b4d1ae9a9b508ce266575244a8d6f32110d7b0b7557b77604869633bb49afbe20035");
				assert.equal(toHex(generators[5].toBytes()), "b95d2898370ebc542857746a316ce32fa5151c31f9b57915e308ee9d1de7db69127d919e984ea0747f5223821b596335");
				assert.equal(toHex(generators[6].toBytes()), "8f19359ae6ee508157492c06765b7df09e2e5ad591115742f2de9c08572bb2845cbf03fd7e23b7f031ed9c7564e52f39");
				assert.equal(toHex(generators[7].toBytes()), "abc914abe2926324b2c848e8a411a2b6df18cbe7758db8644145fefb0bf0a2d558a8c9946bd35e00c69d167aadf304c1");
				assert.equal(toHex(generators[8].toBytes()), "80755b3eb0dd4249cbefd20f177cee88e0761c066b71794825c9997b551f24051c352567ba6c01e57ac75dff763eaa17");
				assert.equal(toHex(generators[9].toBytes()), "82701eb98070728e1769525e73abff1783cedc364adb20c05c897a62f2ab2927f86f118dcb7819a7b218d8f3fee4bd7f");
				assert.equal(toHex(generators[10].toBytes()), "a1f229540474f4d6f1134761b92b788128c7ac8dc9b0c52d59493132679673032ac7db3fb3d79b46b13c1c41ee495bca");
			});

			it("generates the same sequence independent of count", async () => {
				const count1 = 5;
				const count2 = count1 + Math.round(1 + 10*Math.random());
				const generators1 = await create_generators(count1, Bbs.api_id);
				const generators2 = await create_generators(count2, Bbs.api_id);

				assert(generators2.length > generators1.length);
				assert(generators1.every((g1, i) => {
					assert.equal(toHex(g1.toBytes()), toHex(generators2[i].toBytes()));
					return true;
				}));
			});

			it("generates the correct P1", async () => {
				// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-bls12-381-ciphersuites
				const { params: { P1 }, create_generators } = getCipherSuite(
					suiteId,
					{
						create_generators_dsts: {
							sig_generator_seed: toUtf8("H2G_HM2S_SIG_GENERATOR_SEED_"),
							sig_generator_dst: toUtf8("H2G_HM2S_SIG_GENERATOR_DST_"),
							message_generator_seed: toUtf8("H2G_HM2S_BP_MESSAGE_GENERATOR_SEED"),
						},
					}
				);

				const api_id = toUtf8(suiteId);
				const generators = await create_generators(1, api_id);

				assert.equal(generators.length, 1);
				assert.equal(toHex(generators[0].toBytes()), toHex(P1.toBytes()));
				assert.equal(toHex(generators[0].toBytes()), "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9");
			});
		});

		describe("Sign and Verify", () => {
			const { Sign, Verify } = Bbs;

			// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-signature-fixtures-2
			describe("pass test vectors:", async () => {

				const SK = 0x60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fcn;
				const PK = fromHex(
					"a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268" +
					"061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c");
				const header = fromHex("11223344556677889900aabbccddeeff");
				const signature = fromHex(
					"8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641" +
					"d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8");

				it("Valid Single Message Signature", async () => {
					// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-valid-single-message-signatu

					const m_1 = fromHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
					const expectSignature = fromHex(
						"84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0ea" +
						"e615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0");

					const signature = toU8(await Sign(SK, PK, header, [m_1]));

					assert.equal(toHex(signature), toHex(expectSignature));

					const valid = await Verify(PK, signature, header, [m_1]);
					assert.equal(valid, true);

					await asyncAssertThrows(() => Verify(PK, signature, header, null), "Expected signature verification to fail with wrong messages");
					await asyncAssertThrows(() => Verify(PK, signature, header, [m_1, m_1]), "Expected signature verification to fail with wrong messages");
					await asyncAssertThrows(() => Verify(PK, signature, null, [m_1]), "Expected signature verification to fail with wrong header");
					await asyncAssertThrows(() => Verify(PK, signature, concat(header, header), [m_1]), "Expected signature verification to fail with wrong header");
					const modSig = concat(new Uint8Array([signature[0] ^ 0x01]), signature.slice(1));
					await asyncAssertThrows(() => Verify(PK, modSig, header, [m_1]), "Expected signature verification to fail with wrong signature");
				});

				it("Valid Multi-Message Signature", async () => {
					// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-valid-multi-message-signatur
					assert.equal(toHex(await Sign(SK, PK, header, messages)), toHex(signature));

					const valid = await Verify(PK, signature, header, messages);
					assert.equal(valid, true);

					const reverseMessages = [...messages].reverse();
					await asyncAssertThrows(() => Verify(PK, signature, header, null), "Expected signature verification to fail with wrong messages");
					await asyncAssertThrows(() => Verify(PK, signature, header, messages.slice(0, 9)), "Expected signature verification to fail with wrong messages");
					await asyncAssertThrows(() => Verify(PK, signature, header, reverseMessages), "Expected signature verification to fail with wrong messages");
					await asyncAssertThrows(() => Verify(PK, signature, null, messages), "Expected signature verification to fail with wrong header");
					await asyncAssertThrows(() => Verify(PK, signature, concat(header, header), messages), "Expected signature verification to fail with wrong header");
					const modSig = concat(new Uint8Array([signature[0] ^ 0x01]), signature.slice(1));
					await asyncAssertThrows(() => Verify(PK, modSig, header, messages), "Expected signature verification to fail with wrong signature");
				});

				// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-no-header-valid-signature-2
				it("No Header Valid Signature", async () => {
					const header = fromHex("");
					const expectSignature = fromHex(
						"8c87e2080859a97299c148427cd2fcf390d24bea850103a9748879039262ecf4f42206f6ef767f29" +
						"8b6a96b424c1e86c26f8fba62212d0e05b95261c2cc0e5fdc63a32731347e810fd12e9c58355aa0d");

					const signature = toU8(await Sign(SK, PK, header, messages));
					assert.equal(toHex(signature), toHex(expectSignature));

					const valid = await Verify(PK, signature, header, messages);
					assert.equal(valid, true);
				});

				// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-modified-message-signature-2
				it("Modified Message Signature", async () => {
					const modifiedMessages = [""].map(fromHex);
					const signature = fromHex(
						"84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0ea" +
						"e615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0");

					assert.equal(toHex(await Sign(SK, PK, header, [messages[0]])), toHex(signature));
					await asyncAssertThrows(() => Verify(PK, signature, header, modifiedMessages), "Expected negative test case to fail signature verification");
				});

				// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-extra-unsigned-message-signa
				it("Extra Unsigned Message Signature", async () => {
					const modifiedMessages = [
						"9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
						"c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80", // Omitted in signature
					].map(fromHex);
					const signature = fromHex(
						"84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0ea" +
						"e615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0");

					assert.equal(toHex(await Sign(SK, PK, header, [messages[0]])), toHex(signature));
					await asyncAssertThrows(() => Verify(PK, signature, header, modifiedMessages), "Expected negative test case to fail signature verification");
				});

				// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-missing-message-signature-2
				it("Missing Message Signature", async () => {
					const modifiedMessages = [
						"9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
						"c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
					].map(fromHex);

					assert.equal(toHex(await Sign(SK, PK, header, messages)), toHex(signature));
					await asyncAssertThrows(() => Verify(PK, signature, header, modifiedMessages), "Expected negative test case to fail signature verification");
				});

				// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-reordered-message-signature-2
				it("Reordered Message Signature", async () => {
					const modifiedMessages = [
						"",
						"96012096",
						"ac55fb33a75909ed",
						"d183ddc6e2665aa4e2f088af",
						"515ae153e22aae04ad16f759e07237b4",
						"496694774c5604ab1b2544eababcf0f53278ff50",
						"77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
						"7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
						"c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
						"9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
					].map(fromHex);

					assert.equal(toHex(await Sign(SK, PK, header, messages)), toHex(signature));
					await asyncAssertThrows(() => Verify(PK, signature, header, modifiedMessages), "Expected negative test case to fail signature verification");
				});

				// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-wrong-public-key-signature-2
				it("Wrong Public Key Signature", async () => {
					const wrongPK = fromHex(
						"b064bd8d1ba99503cbb7f9d7ea00bce877206a85b1750e5583dd9399828a4d20610cb937ea928d90404c239b2835ffb1" +
						"04220a9c66a4c9ed3b54c0cac9ea465d0429556b438ceefb59650ddf67e7a8f103677561b7ef7fe3c3357ec6b94d41c6");

					assert.equal(toHex(await Sign(SK, PK, header, messages)), toHex(signature));
					await asyncAssertThrows(() => Verify(wrongPK, signature, header, messages), "Expected negative test case to fail signature verification");
				});

				// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-wrong-header-signature-2
				it("Wrong Header Signature", async () => {
					const wrongHeader = fromHex("ffeeddccbbaa00998877665544332211");

					assert.equal(toHex(await Sign(SK, PK, header, messages)), toHex(signature));
					await asyncAssertThrows(() => Verify(PK, signature, wrongHeader, messages), "Expected negative test case to fail signature verification");
				});
			});
		});

		describe("ProofGen and ProofVerify", () => {
			// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-proof-fixtures-2
			describe("pass test vectors:", async () => {

				const defaultBbs = Bbs;
				const { Bbs: { ProofGen, ProofVerify } } = getCipherSuite(
					suiteId,
					{
						// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-mocked-random-scalars
						mocked_random_scalars_params: {
							SEED: fromHex("332e313431353932363533353839373933323338343632363433333833323739"),
							DST: concat(defaultBbs.api_id, toUtf8("MOCK_RANDOM_SCALARS_DST_")),
						},
					},
				);

				const public_key = fromHex(
					"a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268" +
					"061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c");
				const header = fromHex("11223344556677889900aabbccddeeff");
				const presentation_header = fromHex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");
				const signature = fromHex(
					"8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641" +
					"d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8");

				// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-valid-single-message-proof-2
				it("Valid Single Message Proof", async () => {
					const m_0 = messages[0];
					const signature = fromHex(
						"84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0e" +
						"ae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0");
					const revealed_indexes = [0];
					const expectProof = fromHex(
						"94916292a7a6bade28456c601d3af33fcf39278d6594b467e128a3f83686a104ef2b2fcf72df0215eeaf69262ffe8194" +
						"a19fab31a82ddbe06908985abc4c9825788b8a1610942d12b7f5debbea8985296361206dbace7af0cc834c80f33e0aad" +
						"aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a" +
						"49f21d592f5e634f47cee05a025a2f8f94e73a6c15f02301d1178a92873b6e86" +
						"34bafe4983c3e15a663d64080678dbf29417519b78af042be2b3e1c4d08b8d52" +
						"0ffab008cbaaca5671a15b22c239b38e940cfeaa5e72104576a9ec4a6fad78c5" +
						"32381aeaa6fb56409cef56ee5c140d455feeb04426193c57086c9b6d397d9418");

					const proof = await ProofGen(public_key, signature, header, presentation_header, [m_0], revealed_indexes);
					assert.equal(toHex(proof), toHex(expectProof));

					const valid = await ProofVerify(public_key, proof, header, presentation_header, [m_0], revealed_indexes);
					assert.equal(valid, true);

					await asyncAssertThrows(() => ProofVerify(public_key, proof, header, presentation_header, [], []), "Expected proof verification to fail with fewer revealed messages");
				});

				// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-valid-multi-message-all-mess
				it("Valid Multi-Message, All Messages Disclosed Proof", async () => {
					const revealed_indexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
					const expectProof = fromHex(
						"b1f468aec2001c4f54cb56f707c6222a43e5803a25b2253e67b2210ab2ef9eab52db2d4b379935c4823281eaf767fd37" +
						"b08ce80dc65de8f9769d27099ae649ad4c9b4bd2cc23edcba52073a298087d2495e6d57aaae051ef741adf1cbce65c64" +
						"a73c8c97264177a76c4a03341956d2ae45ed3438ce598d5cda4f1bf9507fecef47855480b7b30b5e4052c92a4360110c" +
						"67327365763f5aa9fb85ddcbc2975449b8c03db1216ca66b310f07d0ccf12ab4" +
						"60cdc6003b677fed36d0a23d0818a9d4d098d44f749e91008cf50e8567ef9367" +
						"04c8277b7710f41ab7e6e16408ab520edc290f9801349aee7b7b4e318e6a76e0" +
						"28e1dea911e2e7baec6a6a174da1a22362717fbae1cd961d7bf4adce1d31c2ab");

					const proof = await ProofGen(public_key, signature, header, presentation_header, messages, revealed_indexes);
					assert.equal(toHex(proof), toHex(expectProof));

					const valid = await ProofVerify(public_key, proof, header, presentation_header, messages, revealed_indexes);
					assert.equal(valid, true);

					const reverseMessages = [...messages].reverse();
					await asyncAssertThrows(() => ProofVerify(public_key, proof, header, presentation_header, [], []), "Expected proof verification to fail with no revealed messages");
					await asyncAssertThrows(() => ProofVerify(public_key, proof, header, presentation_header, messages.slice(0, 9), revealed_indexes.slice(0, 9)), "Expected proof verification to fail with fewer revealed messages");
					await asyncAssertThrows(() => ProofVerify(public_key, proof, header, presentation_header, reverseMessages, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]), "Expected proof verification to fail with reversed messages");
				});

				// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-valid-multi-message-some-mes
				it("Valid Multi-Message, Some Messages Disclosed Proof", async () => {
					const revealed_indexes = [0, 2, 4, 6];
					const expectProof = fromHex(
						"a2ed608e8e12ed21abc2bf154e462d744a367c7f1f969bdbf784a2a134c7db2d340394223a5397a3011b1c340ebc4151" +
						"99462ba6f31106d8a6da8b513b37a47afe93c9b3474d0d7a354b2edc1b88818b063332df774c141f7a07c48fe50d452f" +
						"897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac48135" +
						"6918cd38025d86b28650e909defe9604a7259f44386b861608be742af7775a2e" +
						"71a6070e5836f5f54dc43c60096834a5b6da295bf8f081f72b7cdf7f3b4347fb" +
						"3ff19edaa9e74055c8ba46dbcb7594fb2b06633bb5324192eb9be91be0d33e45" +
						"3b4d3127459de59a5e2193c900816f049a02cb9127dac894418105fa1641d5a2" +
						"06ec9c42177af9316f433417441478276ca0303da8f941bf2e0222a43251cf5c" +
						"2bf6eac1961890aa740534e519c1767e1223392a3a286b0f4d91f7f25217a786" +
						"2b8fcc1810cdcfddde2a01c80fcc90b632585fec12dc4ae8fea1918e9ddeb941" +
						"4623a457e88f53f545841f9d5dcb1f8e160d1560770aa79d65e2eca8edeaecb7" +
						"3fb7e995608b820c4a64de6313a370ba05dc25ed7c1d185192084963652f2870" +
						"341bdaa4b1a37f8c06348f38a4f80c5a2650a21d59f09e8305dcd3fc3ac30e2a");

					const proof = await ProofGen(public_key, signature, header, presentation_header, messages, revealed_indexes);
					assert.equal(toHex(proof), toHex(expectProof));

					const revealed_messages = [messages[0], messages[2], messages[4], messages[6]];
					const valid = await ProofVerify(public_key, proof, header, presentation_header, revealed_messages, revealed_indexes);
					assert.equal(valid, true);

					const reverseMessages = [...revealed_messages].reverse();
					await asyncAssertThrows(() => ProofVerify(public_key, proof, header, presentation_header, [], []), "Expected proof verification to fail with no revealed messages");
					await asyncAssertThrows(() => ProofVerify(public_key, proof, header, presentation_header, revealed_messages.slice(0, 3), revealed_indexes.slice(0, 3)), "Expected proof verification to fail with fewer revealed messages");
					await asyncAssertThrows(() => ProofVerify(public_key, proof, header, presentation_header, reverseMessages, [0, 2, 4, 6]), "Expected proof verification to fail with reversed messages");
				});

				// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-no-header-valid-proof-2
				it("No Header Valid Proof", async () => {
					const revealed_indexes = [0, 2, 4, 6];
					const header = fromHex("");
					const signature = fromHex(
						"8c87e2080859a97299c148427cd2fcf390d24bea850103a9748879039262ecf4f42206f6ef767f29" +
						"8b6a96b424c1e86c26f8fba62212d0e05b95261c2cc0e5fdc63a32731347e810fd12e9c58355aa0d");
					const expectProof = fromHex(
						"81925c2e525d9fbb0ba95b438b5a13fff5874c7c0515c193628d7d143ddc3bb487771ad73658895997a88dd5b254ed29" +
						"abc019bfca62c09b8dafb37e5f09b1d380e084ec3623d071ec38d6b8602af93aa0ddbada307c9309cca86be16db53dc7" +
						"ac310574f509c712bb1a181d64ea3c1ee075c018a2bc773e2480b5c033ccb9bfea5af347a88ab83746c9342ba76db367" +
						"5ff70ce9006d166fd813a81b448a632216521c864594f3f92965974914992f8d" +
						"1845230915b11680cf44b25886c5670904ac2d88255c8c31aea7b072e9c4eb7e" +
						"4c3fdd38836ae9d2e9fa271c8d9fd42f669a9938aeeba9d8ae613bf11f489ce9" +
						"47616f5cbaee95511dfaa5c73d85e4ddd2f29340f821dc2fb40db3eae5f5bc08" +
						"467eb195e38d7d436b63e556ea653168282a23b53d5792a107f85b1203f82aab" +
						"46f6940650760e5b320261ffc0ca5f15917b51e7d2ad4bcbec94de792e229db6" +
						"63abff23af392a5e73ce115c27e8492ec24a0815091c69874dbd9dae2d2eed00" +
						"0810c748a798a78a804a39034c6e745cee455812cc982eea7105948b2cb55b82" +
						"278a77237fcbec4748e2d2255af0994dd09dba8ac60515a39b24632a2c1c840c" +
						"4a70506add5b2eb0be9ff66e3ea8deae666f198edfbb1391c6834e6df4f1026d");

					const revealed_messages = [messages[0], messages[2], messages[4], messages[6]];
					const proof = await ProofGen(public_key, signature, header, presentation_header, messages, revealed_indexes);
					assert.equal(toHex(proof), toHex(expectProof));
					assert.equal(await ProofVerify(public_key, proof, header, presentation_header, revealed_messages, revealed_indexes), true);
				});

				// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-no-presentation-header-valid
				it("No Presentation Header Valid Proof", async () => {
					const revealed_indexes = [0, 2, 4, 6];
					const presentation_header = fromHex("");
					const signature = fromHex(
						"8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641" +
						"d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8");
					const expectProof = fromHex(
						"a2ed608e8e12ed21abc2bf154e462d744a367c7f1f969bdbf784a2a134c7db2d340394223a5397a3011b1c340ebc4151" +
						"99462ba6f31106d8a6da8b513b37a47afe93c9b3474d0d7a354b2edc1b88818b063332df774c141f7a07c48fe50d452f" +
						"897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac48135" +
						"672556358e78b5398f1a547a2a98dfe16230f244ba742dea737e4f810b4d94e0" +
						"3ac068ef840aaadf12b2ed51d3fb774c2a0a620019fd1f39c52c6f89a0e6067e" +
						"3039413a91129791b2af215a82ad2356b6bc305c1d7a828fe519619dd026eaaf" +
						"07ea81cee52b21aab3e8320519bf37c2bb228a8b580f899d84327bdc5e84a660" +
						"00e8bac17d2fa039bb2246c8eacc623ccd9eb26e184a96a9e3a6702e1dbafe19" +
						"4772394b05251f72bcd2d20f542b15b2406f899791f6f285c7b469e7c7b96241" +
						"47f305c38c903273a949f6e85b9774aeeccfafa432e2cdd7c8f97d1687741ed3" +
						"0d725444428dd87d9884711d9a46baaf0c04b03a2a228b7033be0841880134b0" +
						"3b15f698756eca5f37503a0411a9586d3027a8b8b9118e95a9949b2719e85e4a" +
						"669d9e4b7bb6d4544c8cc558c30d79f9c85a87e1a95611400b7c7dac5673d800");

					const revealed_messages = [messages[0], messages[2], messages[4], messages[6]];
					const proof = await ProofGen(public_key, signature, header, presentation_header, messages, revealed_indexes);
					assert.equal(toHex(proof), toHex(expectProof));
					assert.equal(await ProofVerify(public_key, proof, header, presentation_header, revealed_messages, revealed_indexes), true);
				});
			});
		});

		describe("Blind BBS", async () => {
			const { BlindBbs } = suite;

			describe("create_generators (non-blind)", () => {
				const { create_unblind_generators } = BlindBbs;

				it("passes test vectors", async () => {
					// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-generators
					const count = 11;
					const generators = await create_unblind_generators(count);
					const [Q1, ...H] = generators;

					assert.equal(generators.length, count);
					assert.equal(toHex(Q1.toBytes()), "8aa0382ea3cd294680e3425bb0bb9293210a4d3e94d8ba59096fcb24eb9b56546645bea83e170b078ff3cc5aeac18c49");
					assert.equal(toHex(H[0].toBytes()), "8065ec88f9bbee345b44e7825b2d602c91b0398b7c885d722450459c26efb1619eb4249428644b9e3d8d11d469d0c62b");
					assert.equal(toHex(H[1].toBytes()), "b96f3af9abcd3ee2228fbe97d4e5a0ef10aaf655c6889e284f27a732492ecdb64a91f92dbaa93f2a7fb550659935985f");
					assert.equal(toHex(H[2].toBytes()), "a99d1b53cc51738a46a7e1fe9b9d89a57977154dcccb7ce741eb779bf69ff655b110f0e97c4715616401e5a47d2c373a");
					assert.equal(toHex(H[3].toBytes()), "9791c624fec3d688975f9c9143f066404115e0dcc1e318ef4f5290c0103ee4a2857dbf9347d997ee507ab629216797f6");
					assert.equal(toHex(H[4].toBytes()), "8a472740d4968c831a3ad3d3c55ada8aca8478e4d0698ece52eff445d15aec1a479332e34562e80831b9593c85b435ec");
					assert.equal(toHex(H[5].toBytes()), "b5102a6529b39de47c136de78a8697395e11013f8aa91f695f158009b52985adee67a63fc354846b7f4b944349295c95");
					assert.equal(toHex(H[6].toBytes()), "845df3031a580f6c58b6d324f42f2158088a924dab9e77151851408a8bda31c266000c10bc47cc38aa3ac24dad22462c");
					assert.equal(toHex(H[7].toBytes()), "b4296c820736cafb7c9229cf499788314a4578de69e88832ca39babe36c48073e61968ae320f9bae61079724a5271eac");
					assert.equal(toHex(H[8].toBytes()), "9253f55dacd9e144f6da37f4adb420773325d142d900a6ae7de851c2643532e0b9181ae3ee02fe8c123b10dd12822876");
					assert.equal(toHex(H[9].toBytes()), "979a52e753c367e3baa8826e7b74a23856abca5468ba5ce5719b4c57eb7e9ee879935f98fbd6959661d3e866477063b2");
				});
			});

			describe("create_generators (blind)", () => {
				const { create_blind_generators } = BlindBbs;

				it("passes test vectors", async () => {
					// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-blind-generators
					const count = 6;
					const generators = await create_blind_generators(count);
					const [Q2, ...J] = generators;

					assert.equal(generators.length, count);
					assert.equal(toHex(Q2.toBytes()), "a347532dc0ba9b83e4f15f3eeb7dffd934f5fa4668d927fbcb68096d5a26f6e59f66681201be1c263af1a25b6749759c");
					assert.equal(toHex(J[0].toBytes()), "af590ba56aa0e526a0763ae6926347dce988ffb9cc1a0b4510ada06fe08816f5c36a6c7007cc8558e5793f9a2cbae462");
					assert.equal(toHex(J[1].toBytes()), "a9a6e5f3093823745734a2195d80886f47185be6a3e4d00df2bd5996aa9d664e34244ea15e9ad4c41d8825331fcfd5a3");
					assert.equal(toHex(J[2].toBytes()), "a6c1a8fd251a338e25d3ea4e09334ea250f0257783f2be4ce4406798ea9acbce41e7648c7fb1409fcd822396f652c4e7");
					assert.equal(toHex(J[3].toBytes()), "80d1232ee4a5623d7ac5a3912c555f9f6f34716edfe156ae40b6ac19afba58dd18556e49529e39da91aa806c9c55d493");
					assert.equal(toHex(J[4].toBytes()), "b8775d3d2f58cafd808d135de79367f34c9ad22a6a878631fd0b1383541999b16b6f3bae96ab51bb4ab25caf69462473");
				});
			});

			describe("commitment", () => {
				describe("passes test vectors:", async () => {
					const { BlindBbs: { Commit }, params: { curves: { fields: { Fr } } } } = getCipherSuite(
						suiteId,
						{
							// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-mocked-random-scalars
							// with
							// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-commitment
							mocked_random_scalars_params: {
								SEED: toUtf8("3.141592653589793238462643383279"),
								DST: toUtf8("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_"),
							},
						},
					);

					it("valid no committed messages commitment with proof", async () => {
						// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-valid-no-committed-messages
						const [commitment_with_proof, secret_prover_blind] = await Commit([], null);

						// TODO: Update test vectors
						// assert.equal(
							// toHex(commitment_with_proof),
							// "849d3cc626720202cbc1610fc01ab41ce32099af602def0c5" +
							// "79f37dd18b485ef60719275a036bdd8120e7e938c8e1a3d4d" +
							// "0322587441ccc5caf186001b45dd09ee159713c3e3ea0f411" +
							// "f94a5d6665546562d09c093b687a129e464a57e18cdbf5306" +
							// "bcabf3e7cc95f5ba98cdd9bf3768"
						// );
						assert.equal(secret_prover_blind, Fr.fromBytes(fromHex("1b6f406b17aaf92dc7deb911c7cae49756a6623b5c385b5ae6214d7e3d9597f7")));
					});

					it("valid multiple committed messages commitment with proof", async () => {
						// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-valid-multiple-committed-me
						const [commitment_with_proof, secret_prover_blind] = await Commit([
							fromHex("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"),
							fromHex("a75d8b634891af92282cc81a675972d1929d3149863c1fc0"),
							fromHex("835889a40744813a892eff9deb1edaeb"),
							fromHex("e1ca9729410dc6ba"),
							fromHex(""),
						], null);

						// TODO: Update test vectors
						// assert.equal(
							// toHex(commitment_with_proof),
							// "a2a3e178bcc77f98a3c07f8532134021ab5847326b5b3bfc3" +
							// "089ca73f1bc51cfe2c99163f4919525dd6bedc8a14ee39e30" +
							// "374643902017ca2e6fb8b5647c736e82d1d3c5b05de5c3021" +
							// "fa6f40d9f36dd22fa06e522411aa20377088ca9a15885d7a5" +
							// "044175f0168e927149ee71e2d257079e0100d6d96a7ddf539" +
							// "2dbc64267af8df7b4711cb5eeccb5e8901d0580b9e837f383" +
							// "37cb7260cffcf4f962154fafe5c98beaed7e4d2fc0f8e7eb1" +
							// "ba4eb04086f170aa4924894e2ab63054049c9ef5dfff4f90b" +
							// "48ef0dcf1f50699907301073270e4782d4d7628cfbe1444ce" +
							// "a930928bb45004e41e0ad86a874ea03473845ce42f78ceb6f" +
							// "855ba8326a4d47732c5aed3968b396a07f079b22b5bf2139e51a03"
						// );
						assert.equal(secret_prover_blind, Fr.fromBytes(fromHex("4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589")));
					});
				});
			});

			describe("signature", () => {
				describe("passes test vectors:", async () => {

					const { BlindBbs: { Commit, BlindSign, VerifyBlindSign }, params: { curves: { fields: { Fr } } } } = getCipherSuite(
						suiteId,
						{
							// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-mocked-random-scalars
							// with
							// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-commitment
							mocked_random_scalars_params: {
								SEED: toUtf8("3.141592653589793238462643383279"),
								DST: toUtf8("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_"),
							},
						},
					);

					// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-signature-test-vectors
					const SK = Fr.fromBytes(fromHex("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc"));
					const PK = fromHex(
						"a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa1" +
						"36f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d46" +
						"0acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63a" +
						"ebc364cd55ded0c"
					);
					const header = fromHex("11223344556677889900aabbccddeeff");

					it("valid no prover committed messages, no signer messages signature", async ({ skip }) => {
						// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-valid-no-prover-committed-m
						const messages = [];
						const committed_messages = [];
						const [commitment_with_proof, secret_prover_blind] = await Commit(committed_messages, null);

						// TODO: Update test vectors
						// assert.equal(
							// toHex(commitment_with_proof),
							// "849d3cc626720202cbc1610fc01ab41ce32099af602def0c5" +
							// "79f37dd18b485ef60719275a036bdd8120e7e938c8e1a3d4d" +
							// "0322587441ccc5caf186001b45dd09ee159713c3e3ea0f411" +
							// "f94a5d6665546562d09c093b687a129e464a57e18cdbf5306" +
							// "bcabf3e7cc95f5ba98cdd9bf3768"
						// );
						assert.equal(secret_prover_blind, Fr.fromBytes(fromHex("1b6f406b17aaf92dc7deb911c7cae49756a6623b5c385b5ae6214d7e3d9597f7")));

						const signature = await BlindSign(SK, PK, commitment_with_proof, null, header, messages);
						const expectedSignature = fromHex(
							"ab54c35fb2af5c75d6368bc5772547e126d60a92205d011bb9ee5d11494" +
							"32e91611fd376fe5b79d6ed7c2ba00a19b7434744945fd77bf02cd4628a" +
							"6e5deeae50768116d55510251bb6a716a38340e184"
						);
						assert(await VerifyBlindSign(PK, signature, header, messages, committed_messages, null, secret_prover_blind));
						assert(await VerifyBlindSign(PK, expectedSignature, header, messages, committed_messages, null, secret_prover_blind));

						skip("signature does not reproduce");
						assert.equal(toHex(signature), toHex(expectedSignature));
					});

					it("valid multi prover committed messages, no signer messages signature", async ({ skip }) => {
						// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-valid-multi-prover-committe
						const messages = [];
						const committed_messages = [
							fromHex("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"),
							fromHex("a75d8b634891af92282cc81a675972d1929d3149863c1fc0"),
							fromHex("835889a40744813a892eff9deb1edaeb"),
							fromHex("e1ca9729410dc6ba"),
							fromHex(""),
						];
						const [commitment_with_proof, secret_prover_blind] = await Commit(committed_messages, null);

						// TODO: Update test vectors
						// assert.equal(
							// toHex(commitment_with_proof),
							// "a2a3e178bcc77f98a3c07f8532134021ab5847326b5b3bfc3" +
							// "089ca73f1bc51cfe2c99163f4919525dd6bedc8a14ee39e30" +
							// "374643902017ca2e6fb8b5647c736e82d1d3c5b05de5c3021" +
							// "fa6f40d9f36dd22fa06e522411aa20377088ca9a15885d7a5" +
							// "044175f0168e927149ee71e2d257079e0100d6d96a7ddf539" +
							// "2dbc64267af8df7b4711cb5eeccb5e8901d0580b9e837f383" +
							// "37cb7260cffcf4f962154fafe5c98beaed7e4d2fc0f8e7eb1" +
							// "ba4eb04086f170aa4924894e2ab63054049c9ef5dfff4f90b" +
							// "48ef0dcf1f50699907301073270e4782d4d7628cfbe1444ce" +
							// "a930928bb45004e41e0ad86a874ea03473845ce42f78ceb6f" +
							// "855ba8326a4d47732c5aed3968b396a07f079b22b5bf2139e51a03"
						// );
						assert.equal(secret_prover_blind, Fr.fromBytes(fromHex("4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589")));

						const signature = await BlindSign(SK, PK, commitment_with_proof, null, header, messages);
						const expectedSignature = fromHex(
							"b7446e6ae4e8b5707ac0108f3b1049e9ea01bd6b2b4a7dcf06e5ad1c62a" +
							"9c0b1585829f0e30fba6c9761469ed908deca52ba5499cef2827b99527b" +
							"4adf1f30522ce32366385ba87594b8d0e44d156eec"
						);
						assert(await VerifyBlindSign(PK, signature, header, messages, committed_messages, null, secret_prover_blind));
						assert(await VerifyBlindSign(PK, expectedSignature, header, messages, committed_messages, null, secret_prover_blind));

						skip("signature does not reproduce");
						assert.equal(toHex(signature), toHex(expectedSignature));
					});

					it("valid no prover committed messages, multiple signer messages signature", async ({ skip }) => {
						// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-valid-no-prover-committed-me
						const messages = [
							fromHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
							fromHex("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
							fromHex("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"),
							fromHex("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"),
							fromHex("496694774c5604ab1b2544eababcf0f53278ff50"),
							fromHex("515ae153e22aae04ad16f759e07237b4"),
							fromHex("d183ddc6e2665aa4e2f088af"),
							fromHex("ac55fb33a75909ed"),
							fromHex("96012096"),
							fromHex(""),
						];
						const committed_messages = [];
						const [commitment_with_proof, secret_prover_blind] = await Commit(committed_messages, null);

						// TODO: Update test vectors
						// assert.equal(
							// toHex(commitment_with_proof),
							// "849d3cc626720202cbc1610fc01ab41ce32099af602def0c5" +
							// "79f37dd18b485ef60719275a036bdd8120e7e938c8e1a3d4d" +
							// "0322587441ccc5caf186001b45dd09ee159713c3e3ea0f411" +
							// "f94a5d6665546562d09c093b687a129e464a57e18cdbf5306" +
							// "bcabf3e7cc95f5ba98cdd9bf3768"
						// );
						assert.equal(secret_prover_blind, Fr.fromBytes(fromHex("1b6f406b17aaf92dc7deb911c7cae49756a6623b5c385b5ae6214d7e3d9597f7")));

						const signature = await BlindSign(SK, PK, commitment_with_proof, null, header, messages);
						const expectedSignature = fromHex(
							"b869cccbe84dce890949db3393c963ead72d044863b2c75bc26c0adfbe0" +
							"8b5bb01db9e4db3313fc660ebb3283634772809d177d191bffde6fe7fbd" +
							"8ca95d7b842e434ae973b7e458325b9eb23b6cf076"
						);
						assert(await VerifyBlindSign(PK, signature, header, messages, committed_messages, null, secret_prover_blind));
						assert(await VerifyBlindSign(PK, expectedSignature, header, messages, committed_messages, null, secret_prover_blind));

						skip("signature does not reproduce");
						assert.equal(toHex(signature), toHex(expectedSignature));
					});

					it("valid multiple signer and prover committed messages signature", async ({ skip }) => {
						// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-valid-multiple-signer-and-p
						const messages = [
							fromHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
							fromHex("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
							fromHex("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"),
							fromHex("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"),
							fromHex("496694774c5604ab1b2544eababcf0f53278ff50"),
							fromHex("515ae153e22aae04ad16f759e07237b4"),
							fromHex("d183ddc6e2665aa4e2f088af"),
							fromHex("ac55fb33a75909ed"),
							fromHex("96012096"),
							fromHex(""),
						];
						const committed_messages = [
							fromHex("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"),
							fromHex("a75d8b634891af92282cc81a675972d1929d3149863c1fc0"),
							fromHex("835889a40744813a892eff9deb1edaeb"),
							fromHex("e1ca9729410dc6ba"),
							fromHex(""),
						];
						const [commitment_with_proof, secret_prover_blind] = await Commit(committed_messages, null);

						// TODO: Update test vectors
						// assert.equal(
							// toHex(commitment_with_proof),
							// "a2a3e178bcc77f98a3c07f8532134021ab5847326b5b3bfc3" +
							// "089ca73f1bc51cfe2c99163f4919525dd6bedc8a14ee39e30" +
							// "374643902017ca2e6fb8b5647c736e82d1d3c5b05de5c3021" +
							// "fa6f40d9f36dd22fa06e522411aa20377088ca9a15885d7a5" +
							// "044175f0168e927149ee71e2d257079e0100d6d96a7ddf539" +
							// "2dbc64267af8df7b4711cb5eeccb5e8901d0580b9e837f383" +
							// "37cb7260cffcf4f962154fafe5c98beaed7e4d2fc0f8e7eb1" +
							// "ba4eb04086f170aa4924894e2ab63054049c9ef5dfff4f90b" +
							// "48ef0dcf1f50699907301073270e4782d4d7628cfbe1444ce" +
							// "a930928bb45004e41e0ad86a874ea03473845ce42f78ceb6f" +
							// "855ba8326a4d47732c5aed3968b396a07f079b22b5bf2139e51a03"
						// );
						assert.equal(secret_prover_blind, Fr.fromBytes(fromHex("4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589")));

						const signature = await BlindSign(SK, PK, commitment_with_proof, null, header, messages);
						const expectedSignature = fromHex(
							"862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea56" +
							"6eb0c3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a" +
							"7a47e2e1ccaa8feb7f3a236e92b2da38462358c48a"
						);
						assert(await VerifyBlindSign(PK, signature, header, messages, committed_messages, null, secret_prover_blind));
						assert(await VerifyBlindSign(PK, expectedSignature, header, messages, committed_messages, null, secret_prover_blind));

						skip("signature does not reproduce");
						assert.equal(toHex(signature), toHex(expectedSignature));
					});

					it("valid no commitment signature", async ({ skip }) => {
						// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-valid-no-commitment-signatu

						const messages = [
							fromHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
							fromHex("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
							fromHex("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"),
							fromHex("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"),
							fromHex("496694774c5604ab1b2544eababcf0f53278ff50"),
							fromHex("515ae153e22aae04ad16f759e07237b4"),
							fromHex("d183ddc6e2665aa4e2f088af"),
							fromHex("ac55fb33a75909ed"),
							fromHex("96012096"),
							fromHex(""),
						];
						const committed_messages = null;
						const commitment_with_proof = null;
						const secret_prover_blind = null;

						const signature = await BlindSign(SK, PK, commitment_with_proof, null, header, messages);
						const expectedSignature = fromHex(
							"8aa8fdfb190987d1fe1c8e34e69eae25594701958064e4483d74580a4a0" +
							"f51f058a87735d727383b864904aa7b5e4a9b3821a18319df0ccb2e351a" +
							"9bf75bf1f34d8858dde57119bfafd8ff56e0c54fa4"
						);
						skip("signature does not verify");
						assert(await VerifyBlindSign(PK, signature, header, messages, committed_messages, null, secret_prover_blind));
						assert(await VerifyBlindSign(PK, expectedSignature, header, messages, committed_messages, null, secret_prover_blind));

						skip("signature does not reproduce");
						assert.equal(toHex(signature), toHex(expectedSignature));
					});
				});
			});

			describe("proof", () => {
				describe("passes test vectors:", async () => {

					const { BlindBbs: { BlindProofGen, BlindProofVerify }, params: { curves: { fields: { Fr } } } } = getCipherSuite(
						suiteId,
						{
							// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-mocked-random-scalars
							// with
							// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-commitment
							mocked_random_scalars_params: {
								SEED: toUtf8("3.141592653589793238462643383279"),
								DST: toUtf8("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_"),
							},
						},
					);

					// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-proof-test-vectors
					const PK = fromHex(
						"a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa1" +
						"36f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d46" +
						"0acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63a" +
						"ebc364cd55ded0c"
					);
					const header = fromHex("11223344556677889900aabbccddeeff");

					it("valid all prover committed messages and signer messages revealed proof", async () => {
						// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-valid-all-prover-committed-
						const signature = fromHex(
							"862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea56" +
							"6eb0c3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a" +
							"7a47e2e1ccaa8feb7f3a236e92b2da38462358c48a"
						);
						const secret_prover_blind = Fr.fromBytes(fromHex("4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589"));
						const presentation_header = fromHex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");
						const messages = [
							fromHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
							fromHex("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
							fromHex("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"),
							fromHex("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"),
							fromHex("496694774c5604ab1b2544eababcf0f53278ff50"),
							fromHex("515ae153e22aae04ad16f759e07237b4"),
							fromHex("d183ddc6e2665aa4e2f088af"),
							fromHex("ac55fb33a75909ed"),
							fromHex("96012096"),
							fromHex(""),
						];
						const committed_messages = [
							fromHex("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"),
							fromHex("a75d8b634891af92282cc81a675972d1929d3149863c1fc0"),
							fromHex("835889a40744813a892eff9deb1edaeb"),
							fromHex("e1ca9729410dc6ba"),
							fromHex(""),
						];

						const disclosed_indexes = messages.map((_, i) => i);
						const disclosed_commitment_indexes = committed_messages.map((_, j) => j);
						const proof = await BlindProofGen(
							PK,
							signature,
							header,
							presentation_header,
							messages,
							committed_messages,
							disclosed_indexes,
							disclosed_commitment_indexes,
							secret_prover_blind,
						);

						assert.equal(
							toHex(proof),
							"a80ea73d954433eca5bff121e0ad4b41e91d2b600cc717eff3804f11ef21cc9" +
							"b9b20da25387722ae6b2dd78103a3413484c3a88248f51c9bfe93cbd88dabc6" +
							"19ba8a432814b15f8dfe601c1cac5404986541968307c8d06acf63ab906c411" +
							"77ba9e5e8f4f1ff77426d3e905b7809243e9ae10acd1013c40525c257e3fe6f" +
							"1bec2a5204433d354f3508eb93e24c91e49b60e8c0bd15af07241c43301024d" +
							"5d8701516307a7b1bb381fbc3bfcaefa4d092519b4996840e199e7e2c40d75d" +
							"593a993ea002fe4d411a9ef650cd0416033ff04d1bb51ca8377b789a2747206" +
							"95c86f5e70ecb56c4abcb3b6ff88edf48677c273ca24547a67e10d4deab8b9c" +
							"989c48d9414b1c05bf61b8f8ae73c9d48c37dec55c1dd59fd821e66b06a117d" +
							"7248b8676e5c15da737cbeb371790a37917130e74"
						);

						const L = 10;
						assert(await BlindProofVerify(
							PK,
							proof,
							header,
							presentation_header,
							L,
							disclosed_indexes.map(i => messages[i]),
							disclosed_commitment_indexes.map(j => committed_messages[j]),
							disclosed_indexes,
							disclosed_commitment_indexes,
						));
					});

					it("valid half prover committed messages and all signer messages revealed proof", async () => {
						// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-valid-half-prover-committed
						const signature = fromHex(
							"862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea56" +
							"6eb0c3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a" +
							"7a47e2e1ccaa8feb7f3a236e92b2da38462358c48a"
						);
						const secret_prover_blind = Fr.fromBytes(fromHex("4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589"));
						const presentation_header = fromHex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");
						const messages = [
							fromHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
							fromHex("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
							fromHex("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"),
							fromHex("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"),
							fromHex("496694774c5604ab1b2544eababcf0f53278ff50"),
							fromHex("515ae153e22aae04ad16f759e07237b4"),
							fromHex("d183ddc6e2665aa4e2f088af"),
							fromHex("ac55fb33a75909ed"),
							fromHex("96012096"),
							fromHex(""),
						];
						const committed_messages = [
							fromHex("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"),
							fromHex("a75d8b634891af92282cc81a675972d1929d3149863c1fc0"),
							fromHex("835889a40744813a892eff9deb1edaeb"),
							fromHex("e1ca9729410dc6ba"),
							fromHex(""),
						];

						const disclosed_indexes = messages.map((_, i) => i);
						const disclosed_commitment_indexes = [0, 2, 4];
						const proof = await BlindProofGen(
							PK,
							signature,
							header,
							presentation_header,
							messages,
							committed_messages,
							disclosed_indexes,
							disclosed_commitment_indexes,
							secret_prover_blind,
						);

						assert.equal(
							toHex(proof),
							"a1fe94ec24e6d325d2494e10bdc395bd82e613e8dd08ca8f4eeffee294246b9" +
							"321cc0e5997de7ae473a4d4c39f27b9088c815c0ff4f8ff7da0ef6d3338e048" +
							"e2b28d98e148e1e8717b6ff6dfc4c74379aab5f409212986ce667c0b9ae4c48" +
							"c278720d66be792af1a62989ea56f433a17f05af1f761b48b9ae2bb24418208" +
							"111680d75c8b7d781186afedbe7c7f293b644cad32737358fed7adc516ec643" +
							"19298fa4d22e2119db88e846f4d8665858b0930016a56245de910baa76242d3" +
							"b2f48d61e78491695773063178c1f35d392198616b619fb5019a17fd6ec0bbb" +
							"f6820cfe6bf8eb58801049465d86aca537126b759f76d65d2239d71584c85c3" +
							"71ff9bc0fd38ebd6623df2cba477ef0ffb0c0c9f35e8a6b4c2c865f4e1b0e5b" +
							"c543601c0a209816a420bd9a6b71e0cf9bc330cc2078c8d74f7c741b2fc6ce3" +
							"e553fe11d4ee2e02b34e81bd06074dfc892b87046a6f77fc07c8857b819c764" +
							"ae92d3779b4bf76f875b4589b37daad83c6bf1889ba"
						);

						const L = 10;
						assert(await BlindProofVerify(
							PK,
							proof,
							header,
							presentation_header,
							L,
							disclosed_indexes.map(i => messages[i]),
							disclosed_commitment_indexes.map(j => committed_messages[j]),
							disclosed_indexes,
							disclosed_commitment_indexes,
						));
					});

					it("valid half prover committed messages and all signer messages revealed proof", async () => {
						// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-valid-half-prover-committed-
						const signature = fromHex(
							"862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea56" +
							"6eb0c3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a" +
							"7a47e2e1ccaa8feb7f3a236e92b2da38462358c48a"
						);
						const secret_prover_blind = Fr.fromBytes(fromHex("4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589"));
						const presentation_header = fromHex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");
						const messages = [
							fromHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
							fromHex("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
							fromHex("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"),
							fromHex("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"),
							fromHex("496694774c5604ab1b2544eababcf0f53278ff50"),
							fromHex("515ae153e22aae04ad16f759e07237b4"),
							fromHex("d183ddc6e2665aa4e2f088af"),
							fromHex("ac55fb33a75909ed"),
							fromHex("96012096"),
							fromHex(""),
						];
						const committed_messages = [
							fromHex("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"),
							fromHex("a75d8b634891af92282cc81a675972d1929d3149863c1fc0"),
							fromHex("835889a40744813a892eff9deb1edaeb"),
							fromHex("e1ca9729410dc6ba"),
							fromHex(""),
						];

						const disclosed_indexes = [0, 2, 4, 6, 8];
						const disclosed_commitment_indexes = committed_messages.map((_, j) => j);
						const proof = await BlindProofGen(
							PK,
							signature,
							header,
							presentation_header,
							messages,
							committed_messages,
							disclosed_indexes,
							disclosed_commitment_indexes,
							secret_prover_blind,
						);

						assert.equal(
							toHex(proof),
							"82a7815ebceefbfb5c1728c940b8ec6efe0d64c6c53c5b7e5a01a598f3e904b" +
							"f4eb43f94f3c41c2c73bf86ad6b4d9a6f87b89bb4c08ab7d0aa1afa52de982f" +
							"b5f173b88db16b09a25358489da59d7d8da1f603aa83b55a6664e276e8b2498" +
							"5de93c5ee7b5fe52c329660f963fa3a26b9316aaddbdb83e764fdb4323be987" +
							"0a9d7fa18c9136ad79d06f6de5e820631cd30a1739ba5dd8f204020cf071e8a" +
							"1a5313e4a3eb1ba058c91f37f397976920eff270ff2bb79bdab9dd006752c91" +
							"5b22e2fff4f362a1dd663b2a178bb7ae08d1a6251e39fb11ff14b24a237ff2d" +
							"8be9fe8d0db493dc019535e53dd31c0608543fb69f9fb31d1483514e65edc9c" +
							"5111281409df08b88d333e4cc76fc41a45e49767523813f5e585c562933a6d7" +
							"fd8b664102bd4822ba062ccee37ea50a3c9e03fc642b84c7d422155b61d69e5" +
							"a832e41169bb08748ac245be18e159be1bb343afc170483a8887fe5b889adc4" +
							"3f410529c7fad530084b1cc90f8854d8bf402def3f90e525e4bc99b5b8b8095" +
							"495651f2cb6844b91a7832744954ca5bbf9a4f9c863c6b3485ad58bdb54fa6c" +
							"71058fe29296eab761ab1a2c4be2db749c40f173f8b2e03ec71a4d9d89d0667" +
							"63fd6a055e6a9e42a3b6a153732a42a5be5bfd2cf85b7d"
						);

						const L = 10;
						assert(await BlindProofVerify(
							PK,
							proof,
							header,
							presentation_header,
							L,
							disclosed_indexes.map(i => messages[i]),
							disclosed_commitment_indexes.map(j => committed_messages[j]),
							disclosed_indexes,
							disclosed_commitment_indexes,
						));
					});

					it("valid half prover committed messages and half signer messages revealed proof", async () => {
						// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-valid-half-prover-committed-m
						const signature = fromHex(
							"862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea56" +
							"6eb0c3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a" +
							"7a47e2e1ccaa8feb7f3a236e92b2da38462358c48a"
						);
						const secret_prover_blind = Fr.fromBytes(fromHex("4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589"));
						const presentation_header = fromHex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");
						const messages = [
							fromHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
							fromHex("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
							fromHex("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"),
							fromHex("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"),
							fromHex("496694774c5604ab1b2544eababcf0f53278ff50"),
							fromHex("515ae153e22aae04ad16f759e07237b4"),
							fromHex("d183ddc6e2665aa4e2f088af"),
							fromHex("ac55fb33a75909ed"),
							fromHex("96012096"),
							fromHex(""),
						];
						const committed_messages = [
							fromHex("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"),
							fromHex("a75d8b634891af92282cc81a675972d1929d3149863c1fc0"),
							fromHex("835889a40744813a892eff9deb1edaeb"),
							fromHex("e1ca9729410dc6ba"),
							fromHex(""),
						];

						const disclosed_indexes = [0, 2, 4, 6, 8];
						const disclosed_commitment_indexes = [0, 2, 4];
						const proof = await BlindProofGen(
							PK,
							signature,
							header,
							presentation_header,
							messages,
							committed_messages,
							disclosed_indexes,
							disclosed_commitment_indexes,
							secret_prover_blind,
						);

						assert.equal(
							toHex(proof),
							"906a557b649ef5fa3ae1b17f814bbf1e78936daed6ac985416ce97bdaada5e8" +
							"74d60f34074c5f2a8c02b1c33c3cb041294aa3da2e1bb55674a4b94d860f347" +
							"7be7eb1adb763894796b285df22112a153ad13c35e4b9707046de269833e27c" +
							"16d9621b73f05e4c7c543bf995e76ac1013839c6e8a9909b36e979192c5497b" +
							"cc9fc534aa9296ec36ae43c398cdd328d3b606ebb0642786b508eb1d38893cf" +
							"ffe8c9cff3c385644bd3641e0d1cbeda08bf16902d6dfeefa3ac8f8840a5f15" +
							"5c54695b908e729b7f0d06fa9453d28746dfae608580fab158d2966ed54a3b5" +
							"28346d72d49b0d69576b1094b3b14bfcba67af81c4467b424e9ac53fbf9cf8c" +
							"a7c4cd20ac61243d61d91cd937eb82cb1524e38b24bd0ef235886c9f32e139f" +
							"fe0b371bf1a310dd4a81bdda3994f1c2f85bd4b775dd2b716ad1a06e4b60444" +
							"8a8bad5a75581b8c655652b284b1f727f52fe74ff501990b95918fdac4a00c3" +
							"509bcb978370224b2c38aea21d811f30fcf623aa3f917ca0193ae9fd3ad3f82" +
							"c7e1dd80c5712d280faa027b90d27ffb37fad3ea7bcc5c69885dfe74acfb072" +
							"13d01cd974133e5f6c423d7e3fa118c590cbf5edac814486965aadec1620615" +
							"6c97e37f7ebc837f9482f2b7c97e691bf80d0d4a02ccff38794349ef189ef7e" +
							"7c909dc0c420236abac3be7613c66e41dee0a3246a759225c2e5be0db5131fe" +
							"e3e284bb3bdc98ff34eccb03eb70cac6b8aedef376110de7"
						);

						const L = 10;
						assert(await BlindProofVerify(
							PK,
							proof,
							header,
							presentation_header,
							L,
							disclosed_indexes.map(i => messages[i]),
							disclosed_commitment_indexes.map(j => committed_messages[j]),
							disclosed_indexes,
							disclosed_commitment_indexes,
						));
					});

					it("valid no prover committed messages and half signer messages revealed proof", async () => {
						// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-valid-no-prover-committed-mes
						const signature = fromHex(
							"862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea56" +
							"6eb0c3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a" +
							"7a47e2e1ccaa8feb7f3a236e92b2da38462358c48a"
						);
						const secret_prover_blind = Fr.fromBytes(fromHex("4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589"));
						const presentation_header = fromHex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");
						const messages = [
							fromHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
							fromHex("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
							fromHex("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"),
							fromHex("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"),
							fromHex("496694774c5604ab1b2544eababcf0f53278ff50"),
							fromHex("515ae153e22aae04ad16f759e07237b4"),
							fromHex("d183ddc6e2665aa4e2f088af"),
							fromHex("ac55fb33a75909ed"),
							fromHex("96012096"),
							fromHex(""),
						];
						const committed_messages = [
							fromHex("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"),
							fromHex("a75d8b634891af92282cc81a675972d1929d3149863c1fc0"),
							fromHex("835889a40744813a892eff9deb1edaeb"),
							fromHex("e1ca9729410dc6ba"),
							fromHex(""),
						];

						const disclosed_indexes = [0, 2, 4, 6, 8];
						const disclosed_commitment_indexes = [];
						const proof = await BlindProofGen(
							PK,
							signature,
							header,
							presentation_header,
							messages,
							committed_messages,
							disclosed_indexes,
							disclosed_commitment_indexes,
							secret_prover_blind,
						);

						assert.equal(
							toHex(proof),
							"98805466f2fb4858dd9f60cfdc24d73b5192df64fce827b6ce942a6f2c8d5b3" +
							"3f7eb7bf178353cf4bac91a4d6b84b536a89f504e4b46dea57ed2bc29d83993" +
							"d71fb0b5a012d36aa8c3f0ba25220435be5f1b632166228bbb496eaebc1e382" +
							"67eb46b5550d6e4d32d2f5559ada94828f729cac8f192a8fdb7aac7ffcf0102" +
							"fef68314723ded1927965f30096e5f89103a036f32fb9980015f9d7781f86e6" +
							"61e90d7b01f4c4c1bca0f7e0101098d9abcb603c3945c14b8cb298eecda9e7a" +
							"8271dd407e68a45c4d2d4842b7095392873ccb4f2a0136ed04e9410b8c65ece" +
							"d108f5b87b9c5b84c5ff95d3345f410d8a0efd51b5d24978c578859f2183cac" +
							"affc17c031c24dc58ffc29d46922e16672140d1b078b8e7e9f87d31663ee497" +
							"90274b2735bc807562c8e76f3223925ad2c15093e118ed7ec82eb590d8a9227" +
							"408339f4091363da652e68cdf02c0003c94e35a2085d621447c2b0840b22af2" +
							"a5d62fea5e898dba51d93bdd5f23c6b448f722d95d70459fd68f59b617adeb6" +
							"2b0441745b0d69e865e0fc956359e137cf4706286a9764e6b7efd431cde5988" +
							"76b992196c15662ba6c6768ad0ed4291963ac304dfa951c41d7233d6d85d2a9" +
							"ff903468590ea787d413205b56d1892fa666230c93a87756d96fe3832930f01" +
							"826651f8f449a945c0a3a9b50472c2060eceb566ec39961685560f49c36b500" +
							"31dc8b4339da942e5c25498919a812209bbff527c332a5e50f27a539f805caa" +
							"7c1a774034906d2aae0b6c2db4696d3ed91453ea0f1e42d4129a9812dbddec7" +
							"1d55d3ec1598202db88e15f3ad7f8eef3098102be8f978785e2327ce643cc12" +
							"df227ef05f13ab395a6d318c59e2195d410e768cdf9e7a1784c"
						);

						const L = 10;
						assert(await BlindProofVerify(
							PK,
							proof,
							header,
							presentation_header,
							L,
							disclosed_indexes.map(i => messages[i]),
							disclosed_commitment_indexes.map(j => committed_messages[j]),
							disclosed_indexes,
							disclosed_commitment_indexes,
						));
					});

					it("valid half prover committed messages and no signer messages revealed proof", async () => {
						// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-valid-half-prover-committed-me
						const signature = fromHex(
							"862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea56" +
							"6eb0c3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a" +
							"7a47e2e1ccaa8feb7f3a236e92b2da38462358c48a"
						);
						const secret_prover_blind = Fr.fromBytes(fromHex("4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589"));
						const presentation_header = fromHex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");
						const messages = [
							fromHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
							fromHex("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
							fromHex("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"),
							fromHex("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"),
							fromHex("496694774c5604ab1b2544eababcf0f53278ff50"),
							fromHex("515ae153e22aae04ad16f759e07237b4"),
							fromHex("d183ddc6e2665aa4e2f088af"),
							fromHex("ac55fb33a75909ed"),
							fromHex("96012096"),
							fromHex(""),
						];
						const committed_messages = [
							fromHex("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"),
							fromHex("a75d8b634891af92282cc81a675972d1929d3149863c1fc0"),
							fromHex("835889a40744813a892eff9deb1edaeb"),
							fromHex("e1ca9729410dc6ba"),
							fromHex(""),
						];

						const disclosed_indexes = [];
						const disclosed_commitment_indexes = [0, 2, 4];
						const proof = await BlindProofGen(
							PK,
							signature,
							header,
							presentation_header,
							messages,
							committed_messages,
							disclosed_indexes,
							disclosed_commitment_indexes,
							secret_prover_blind,
						);

						assert.equal(
							toHex(proof),
							"aff98a4a0bc336e459d47c19816f372de628581bc626fdd20e907db10d2218d" +
							"d47530fbebc78afed77f2557d344d620d9097016e84b0dc7588686bbeacb44f" +
							"c55bb3004bf79e89d82ed37df3e1835975cc63a00b76685eecc4aff51426fb4" +
							"3cb87d8ba852fb786f1cf649271517bcc4bb72af3e3b2fa4ae57bea485b6f98" +
							"86fe33d0e5bd95d21f4ccaa4d80b64692caa23d32c7368ef99f1b9ab1672ecb" +
							"3ae7393a3a4d3efa6f4dc18d8563788f97d8b3fb7427593bdc21aed4332d17b" +
							"94d82b8c20ea1236a756a4ec2cfa5e1050588e04582299196c1f28e04c2349c" +
							"5d9e717ba6a581ed255f20bf4210f852d2cd95844fdaacf4d8339a14fe7982b" +
							"e4f447812616433a3e23990c180ec2540c13f9d467e996cd9a2df2bdd1b0bfe" +
							"3e51c116e13888d21e26ee61d7ca070968bc13e9d3d33dce20dfc52618bfa4d" +
							"340f558660f41d67d11f5af9a1e185f261a2d14eb667987d700ce77ed24e3b7" +
							"0c29e49c188b5963dfb16ab7c2439ec6824f738e3df128865e180a41b06b1db" +
							"ad2eed8a82728fc4dd34046410345c38415d9daaa3076efbbf84b8f3c52c2bf" +
							"527d10ae882b0790a7f3b6b3e2c877fbb5a7d18bda860278598f1a83c855e67" +
							"e3b8f8d807b29514d2420753ace9356a39e70fe49c5f2e29cea65820b57f3b2" +
							"5363685a5559c577ca48046d5eaa35568a935f58dbd9dae2744eb4dfe33cbb6" +
							"6bc2b351f2b634f508fe2e37ae19c89f14b4d6d6f636890d62e0f4ccb9565d4" +
							"f8786b429188c7351f08538aff7b760da7867683315700ab549b639a59b9025" +
							"fbf67ffb34a834d8b9e893d9d5969e9022813c4529115e682758166b4d2b8af" +
							"72f44b00dff7b769bb985c40bef59e18034febfd7bb5ee847b13160b0da82b2" +
							"8cd400c53ff004038e67b9fd49511f9e8b69df923f3aa73fb1636f1ee88214b" +
							"dcd79462a1f7411e0c8ab10a8bba0140c9cddfbcdc88d7ca19dfd"
						);

						const L = 10;
						assert(await BlindProofVerify(
							PK,
							proof,
							header,
							presentation_header,
							L,
							disclosed_indexes.map(i => messages[i]),
							disclosed_commitment_indexes.map(j => committed_messages[j]),
							disclosed_indexes,
							disclosed_commitment_indexes,
						));
					});

					it("valid no prover committed messages and no signer messages revealed proof", async () => {
						// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-valid-no-prover-committed-mess
						const signature = fromHex(
							"862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea56" +
							"6eb0c3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a" +
							"7a47e2e1ccaa8feb7f3a236e92b2da38462358c48a"
						);
						const secret_prover_blind = Fr.fromBytes(fromHex("4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589"));
						const presentation_header = fromHex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");
						const messages = [
							fromHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
							fromHex("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
							fromHex("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"),
							fromHex("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"),
							fromHex("496694774c5604ab1b2544eababcf0f53278ff50"),
							fromHex("515ae153e22aae04ad16f759e07237b4"),
							fromHex("d183ddc6e2665aa4e2f088af"),
							fromHex("ac55fb33a75909ed"),
							fromHex("96012096"),
							fromHex(""),
						];
						const committed_messages = [
							fromHex("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"),
							fromHex("a75d8b634891af92282cc81a675972d1929d3149863c1fc0"),
							fromHex("835889a40744813a892eff9deb1edaeb"),
							fromHex("e1ca9729410dc6ba"),
							fromHex(""),
						];

						const disclosed_indexes = [];
						const disclosed_commitment_indexes = [];
						const proof = await BlindProofGen(
							PK,
							signature,
							header,
							presentation_header,
							messages,
							committed_messages,
							disclosed_indexes,
							disclosed_commitment_indexes,
							secret_prover_blind,
						);

						assert.equal(
							toHex(proof),
							"b27d9bc8c52a582d00db93da283346751c8da54a902703110e511fa39f184ed" +
							"6c464d78c81d4bbcc57b7de1b31c7644184ba8f06266dfa8b2662b756f8c89b" +
							"f3b01f7f66753028dc0ca85a0417a4f6d9dae4b393aaf5c152734f210a790a5" +
							"f96a2ad1aaab7c1f5167484d18bf19570e2fa4d58b481225a1a576286bac7e4" +
							"353aa7cba80939eabc492347fc05f8bd701f5410ecb5faf54d4a617bddf39bc" +
							"b314d750257e99db7f0b03d043f8674668479322dc83c5c1e9e05dd760a4e1b" +
							"5c45a044072bfe4e0f21bea9cc6362a38664532b4e10d0e7c4751452ff30724" +
							"70b6919bded88d3e591e96a4b71603944015ca36594432351d9de6309820d5a" +
							"837e28e690b662a959833fd51faf6b77e7636f206385eee2d3aa1d99758e1ef" +
							"310a914f1a9fa3cd8eb2feb170c13de8e36de2dd2726430e0782cd0d5eaef64" +
							"d11bd871eb27b6b2a9536a4189731b32cd16ee25ba305ee01d99689e66534d5" +
							"8399a514b92813873ed28f377679f3aab6e977d62226dd4fa0eef43f7b69f92" +
							"ca0d69588fb8339ba0b35d1fbc3623fdf2d761fa537d54b0b2cd094a8bf98f1" +
							"117a8f665c5f68f101926f729185a6d830894f4864f606d47b5b5fab349b23b" +
							"9be04443d1d6bef67a1755bcb5ac2d46e8af259bc449ce19edc5a4a20f5d236" +
							"bf6089012df8021ebb68c756aa85528a98aa758a5524cf71ccc9867ec837576" +
							"d092c68844d8ace281fd063343b212399dcd1cc80fd7cbd822e559df5616c81" +
							"eb8e6e7768d8f9819b757d3a1f9211d047bdbb172c26e2e3f0a4541d7e30b05" +
							"d25b6905abba445488543a16729090eb6d0a45cef159f17cea4ebdc307f9191" +
							"d76dc52277cda93c0ae75d8021ced39b064229271d673cf28ec645ba56637ec" +
							"f0f54982f78773cf3ae8514dfcd4932c41337c766e9d9e6041bd0a01062da4a" +
							"d80106520b29888ca5c4893a8b447cf502e6672b038698bf1b7ae0d87c4e546" +
							"ae98c7b6c21ad1fb56d54ee930ba9524c55705c00b05c3b6dd0c3f42ca9f9c0" +
							"6748cdda8c1ca428122e780a80ae78c66c1d02728ea751dce0ac100134eed0a" +
							"a579badf2131c90aea352b28586cd1dc6663008e9e38866a9f383aeb"
						);

						const L = 10;
						assert(await BlindProofVerify(
							PK,
							proof,
							header,
							presentation_header,
							L,
							disclosed_indexes.map(i => messages[i]),
							disclosed_commitment_indexes.map(j => committed_messages[j]),
							disclosed_indexes,
							disclosed_commitment_indexes,
						));
					});

					it("valid all prover committed messages and signer messages revealed proof", async ({ skip }) => {
						// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-valid-all-prover-committed-m
						const signature = fromHex(
							"8aa8fdfb190987d1fe1c8e34e69eae25594701958064e4483d74580a4a0" +
							"f51f058a87735d727383b864904aa7b5e4a9b3821a18319df0ccb2e351a" +
							"9bf75bf1f34d8858dde57119bfafd8ff56e0c54fa4"
						);
						const secret_prover_blind = null;
						const presentation_header = fromHex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");
						const messages = [
							fromHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
							fromHex("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
							fromHex("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"),
							fromHex("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"),
							fromHex("496694774c5604ab1b2544eababcf0f53278ff50"),
							fromHex("515ae153e22aae04ad16f759e07237b4"),
							fromHex("d183ddc6e2665aa4e2f088af"),
							fromHex("ac55fb33a75909ed"),
							fromHex("96012096"),
							fromHex(""),
						];
						const committed_messages = null;

						const disclosed_indexes = [0, 2, 4, 6, 8];
						const disclosed_commitment_indexes = null;
						skip("proof does not succeed");
						const proof = await BlindProofGen(
							PK,
							signature,
							header,
							presentation_header,
							messages,
							committed_messages,
							disclosed_indexes,
							disclosed_commitment_indexes,
							secret_prover_blind,
						);

						skip("proof does not reproduce");
						assert.equal(
							toHex(proof),
							"a8c57d443b888815e25ca197a543c3a007c573cea5d2cc3c7aa312dbe4aa33a" +
							"62490ced4d8f5c0a99aeada24f79b2d34b32cb742dab22663402104828af5e0" +
							"85a6019fb073e08374e9be9b1af64140a4d1ce2b8016f85ebca3ebb5aa02847" +
							"b91936d649f19d0e85a19118e5e13e2beabf2d705e1db59f8945adddafc7731" +
							"0b0a02042093a5477d9efd4a98cb2fad4dc535fa9f5e6a96f744ece30bbf1fc" +
							"ca709d5b4fcc8c390b4e2ad755292cc20817141d9348e4a7d7c864493625c8a" +
							"aa455c486afab64ae63f56c10b90047bbfa20825b2cb00f19ee3b54f7c7bdce" +
							"a55f5811803b9cff2c2f2e96495dd12236e17c9581997b7880062715aa7deec" +
							"4ca4b3b4eebba824cbe0adcba83f8e70bc0004ee350b5365138297983171d9c" +
							"ca33ca2376157f390a724f857b4212fe834898d332a582083b8791969d2a070" +
							"57722a22b44132c5fc2ed0035b3b2e71f9ec08ebc33e019a1fa76bd8d642da2" +
							"1cd0a8b36080203c2c4d5b10411e90b8bebd454040556480519175f28f31210" +
							"870454bfad2905d49e9b655b5bea6318955ba210938b279717a2b1e1d34cccf" +
							"ddfe9c8e3729f6e92e28197a09459c6dcd56e3920a0d73954d79b681f1e93f7" +
							"0566a73f42610c389ec3f0d65a4727229df891a61511d2"
						);

						const L = 10;
						skip("proof does not verify");
						assert(await BlindProofVerify(
							PK,
							proof,
							header,
							presentation_header,
							L,
							disclosed_indexes.map(i => messages[i]),
							null,
							disclosed_indexes,
							disclosed_commitment_indexes,
						));
					});
				});
			});
		});

		describe("BBS-Schnorr", async () => {
			const { Bbs: { BbsSchnorr }, params: { curves: { G1 } } } = suite;

			it("works.", async () => {
				const { iss_kgen, dev_kgen, issue, verify, vf_cred, show_user_1, show_se_1, show_user_2 } = await BbsSchnorr({ l: 3 });

				const [isk, ipk] = await iss_kgen();
				const [dsk, dpk] = await dev_kgen();
				const attrs = [1n, 2n, 3n];
				const sigma = await issue(isk, dpk, attrs);

				assert(vf_cred(ipk, sigma, dpk, attrs));

				const [ust, umsg] = await show_user_1(ipk, dpk, sigma, attrs, toUtf8("Hello, World!"), [1]);
				const smsg = await show_se_1(ipk, dsk, umsg, toUtf8("Hello, World!"));
				const tau = await show_user_2(ust, smsg);

				const smsg2 = await show_se_1(ipk, dsk, umsg, toUtf8("Hello, Worldz!"));
				const tau2 = await show_user_2(ust, smsg2);

				assert(await verify(ipk, toUtf8("Hello, World!"), [1], [2n], tau));
				asyncAssertThrows(() => verify(ipk, toUtf8("Hello, World!"), [1], [2n], tau2), "Expected invalid proof to fail verification");
				asyncAssertThrows(() => verify(ipk, toUtf8("Hello, World!"), [], [], tau), "Expected too few attributes to fail verification");
				asyncAssertThrows(() => verify(ipk, toUtf8("Hello, World!"), [], [2n], tau), "Expected unmatched attributes and indices to fail verification");
				asyncAssertThrows(() => verify(ipk, toUtf8("Hello, World!"), [1], [1n], tau), "Expected incorrect attribute (1) to fail verification");
				asyncAssertThrows(() => verify(ipk, toUtf8("Hello, World!"), [1], [3n], tau), "Expected incorrect attribute (3) to fail verification");
				asyncAssertThrows(() => verify(ipk, toUtf8("Hello, Worldz!"), [1], [2n], tau), "Expected incorrect ctx to fail verification");
				asyncAssertThrows(() => verify(ipk, toUtf8("Hello, World!"), [0, 1], [1n, 2n], tau), "Expected disclosed-and-undisclosed attribute to fail verification");
				asyncAssertThrows(() => verify(ipk.multiply(2), toUtf8("Hello, World!"), [1], [2n], tau), "Expected incorrect issuer public key to fail verification");
			});

			it("works with a SE proof recorded from a hardware device.", async () => {
				const { iss_kgen, issue, verify, vf_cred, show_user_1, show_user_2, schnorr_verify_sha256_encoded } = await BbsSchnorr({ l: 3 });

				const ikm = toUtf8("Test BBS-Schnorr with hardware device");
				const [isk, ipk] = await iss_kgen(ikm);

				// The public key generated by the hardware device
				const dpk_rfc8235: PointG1 = G1.Point.fromHex(
					"a40bb48487058c33a20cd3f841e933a0434b3f8761f5e3c3b4aa3ae7fae42861c1b8ff0fbe970f055895d1ee9771ff44");

				// RFC 8235 computes the public key as `A = G x [a]` with generator G and secret key a,
				// and the signature as `r = v - a*c` with random nonce v, and challenge hash c,
				// and therefore the verification checks the identity `V = G x [r] + A x [c]` with `V = G x [v]`.
				// In https://eprint.iacr.org/2025/1995.pdf the Schnorr signature scheme is written with
				// public key still `pk = sk*H0` with secret key sk and generator H0,
				// but signature as `s = ω + c*sk` with nonce ω,
				// and therefore verification instead checks the identity `R = s*H0 - c*pk` with `R = ω*H0`.
				// Note the flipped signs between signature formulations.
				// Luckily, the two are compatible and can be translated between by simply negating the public key.
				// Identifying `s' = r = v - a*c = ω - c*sk` and `pk = -A = G x [-a] = (-sk)*H0` we get:
				// `R = s'*H0 - c*(-pk) = (ω*H0 - c*sk*H0) - c*pk = (ω*H0 - c*sk*H0) - c*(-sk)*H0 = ω*H0 - c*sk*H0 + c*sk*H0 = ω*H0`
				// so the verification identity `R = s*H0 - c*pk` holds for the signature `r = v - a*c` if the public key is negated.
				const dpk = dpk_rfc8235.negate();

				const attrs = [1n, 2n, 3n];
				const sigma = await issue(isk, dpk, attrs, ikm);

				assert(vf_cred(ipk, sigma, dpk, attrs));

				const ctx = toUtf8("Hello, World!");
				const [ust, umsg] = await show_user_1(ipk, dpk, sigma, attrs, ctx, [1], ikm);
				const tbs = concat(umsg.toBytes(), ctx);

				// This Schnorr signature uses the following construction:
				// - The random nonce scalar is `v`.
				// - The challenge `c` is `c = SHA-256(point_to_octets_E1(V) || msg)`.
				// - `V = G x [v]` as defined in [Section 3.2 of RFC 8235][1].
				// - `point_to_octets_E1` is defined in BBS ciphersuite BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_ [2].
				// - The encoded signature is `OS2IP(r, 32) || OS2IP(c, 32)`.
				// [1]: https://www.rfc-editor.org/rfc/rfc8235.html#section-3.2
				// [2]: https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-10.html#name-bls12-381-sha-256
				const smsg = fromHex(
					"09b2bde332176e47a6233665968d111f3aeadb7571530c3f602e3c43ae546606" +
					"5493335d0120ce9bf4647bc5a1a752e888696248ebdb34b7337538866744428a");
				assert(await schnorr_verify_sha256_encoded(dpk, smsg, tbs));

				const tau = await show_user_2(ust, smsg);
				assert(await verify(ipk, ctx, [1], [2n], tau));
			});

			it("works with a SE proof on H1 recorded from a hardware device.", async () => {
				const { iss_kgen, issue, verify, vf_cred, show_user_1, show_user_2, schnorr_verify_sha256_encoded } = await BbsSchnorr({ l: 3, dpk_uses_h1: true });

				const ikm = toUtf8("Test BBS-Schnorr with hardware device");
				const [isk, ipk] = await iss_kgen(ikm);

				// The public key generated by the hardware device
				const dpk_rfc8235: PointG1 = G1.Point.fromHex(
					"a967e87f22059b61e3da6e164a9073676ec94b1481d3e43b0f70f763fc311525e7d20c899eb78a6c545f96f4f868a6ee");

				// RFC 8235 computes the public key as `A = G x [a]` with generator G and secret key a,
				// and the signature as `r = v - a*c` with random nonce v, and challenge hash c,
				// and therefore the verification checks the identity `V = G x [r] + A x [c]` with `V = G x [v]`.
				// In https://eprint.iacr.org/2025/1995.pdf the Schnorr signature scheme is written with
				// public key still `pk = sk*H0` with secret key sk and generator H0,
				// but signature as `s = ω + c*sk` with nonce ω,
				// and therefore verification instead checks the identity `R = s*H0 - c*pk` with `R = ω*H0`.
				// Note the flipped signs between signature formulations.
				// Luckily, the two are compatible and can be translated between by simply negating the public key.
				// Identifying `s' = r = v - a*c = ω - c*sk` and `pk = -A = G x [-a] = (-sk)*H0` we get:
				// `R = s'*H0 - c*(-pk) = (ω*H0 - c*sk*H0) - c*pk = (ω*H0 - c*sk*H0) - c*(-sk)*H0 = ω*H0 - c*sk*H0 + c*sk*H0 = ω*H0`
				// so the verification identity `R = s*H0 - c*pk` holds for the signature `r = v - a*c` if the public key is negated.
				const dpk = dpk_rfc8235.negate();

				const attrs = [1n, 2n, 3n];
				const sigma = await issue(isk, dpk, attrs, ikm);

				assert(vf_cred(ipk, sigma, dpk, attrs));

				const ctx = toUtf8("Hello, World!");
				const [ust, umsg] = await show_user_1(ipk, dpk, sigma, attrs, ctx, [1], ikm);
				const tbs = concat(umsg.toBytes(), ctx);

				// This Schnorr signature uses the following construction:
				// - The generator point is the H1 generated by the BBS ciphersuite BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_ [1].
				// - The random nonce scalar is `v`.
				// - The challenge `c` is `c = SHA-256(point_to_octets_E1(V) || msg)`.
				// - `V = H1 x [v]` as defined in [Section 3.2 of RFC 8235][2].
				// - `point_to_octets_E1` is defined in BBS ciphersuite BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_ [3].
				// - The encoded signature is `OS2IP(r, 32) || OS2IP(c, 32)`.
				// [1]: https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-10.html#name-message-generators-2
				// [2]: https://www.rfc-editor.org/rfc/rfc8235.html#section-3.2
				// [3]: https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-10.html#name-bls12-381-sha-256
				const smsg = fromHex(
					"4d7777dd270141f00dfc34e8922da9a0f676432f06d1ba5e3aacb840fa64a54b" +
					"6af9c63c7778ae5536a1d8e8129042470c60b62da0e30db80f7e0cf56ffd79e2");
				assert(await schnorr_verify_sha256_encoded(dpk, smsg, tbs));

				const tau = await show_user_2(ust, smsg);
				assert(await verify(ipk, ctx, [1], [2n], tau));
			});
		});
	});
});
