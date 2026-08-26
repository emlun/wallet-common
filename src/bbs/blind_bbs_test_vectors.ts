import { sha256 } from "../arkg/hash_to_curve";
import { concat, fromHex, fromUtf8, OS2IP, range, toHex, toUtf8 } from "../utils/util";
import { CipherSuite, DisclosureChoice, getCipherSuite, PointG1, SchnorrSignatureScheme, SignatureScheme, SuiteId } from "./blind_bbs";


type TestVectorCase = { title: string, content: string };
type TestVectorSubsection = { title: string, test_cases: TestVectorCase[] };
type TestVectorSection = { suite_id: string, suite_description: string, subsections: TestVectorSubsection[] };

const keybindSuites: { suiteId: SuiteId, SigConstructor?: (Bbs: CipherSuite) => SignatureScheme }[] = [
	{
		suiteId: 'BBS-SCHNORR_BLS12381G1_XMD:SHA-256_SSWU_RO_',
		SigConstructor: (suite: CipherSuite) => SchnorrSignatureScheme(
			suite.Bbs,
			async (msg) => OS2IP(await sha256(msg)),
			async () => (await suite.Bbs.real_calculate_random_scalars(1))[0],
			(Hk: PointG1, SK: bigint, message: BufferSource, i: number) =>
				suite.Bbs.hash_to_scalar(concat(suite.Bbs.serialize([SK, i]), message), concat(toUtf8("TEST-VECTORS_"), suite.BlindBbs.api_id)),
		),
	},
	{ suiteId: 'BBS-BLS_BLS12381G1_XMD:SHA-256_SSWU_RO_' },
];

function format_list(indent: number, items: string[], wrap?: boolean): string {
	if (items.length === 0) {
		return '[]';
	} else {
		const wrapf = wrap ? (s: string) => wrap_string(indent + 2, s) : (s: string) => s;
		const indentation = new Array(indent).fill(" ").join("");
		const final_indentation = new Array(indent - 2).fill(" ").join("");
		return `[
${items.map(s => wrapf(`${indentation}${s},`)).join("\n")}
${final_indentation}]`;
	}
}

function wrap_string(indent: number, s: string): string {
	const width = 72;
	if (s.length <= width) {
		return s;
	}
	const indented_width = width - indent;
	const indentation = new Array(indent).fill(" ").join("");
	return range(Math.ceil(Math.floor(Math.min(s.length, width) / width) + (s.length - width) / indented_width))
		.map(i => i === 0
			? s.substring(0, width)
			: indentation + s.substring(indent + i * indented_width, indent + (i + 1) * indented_width)
		)
		.join("\n");
}

function make_test_vector_case(title: string, content: string): TestVectorCase {
	return { title, content };
}

async function generate_keybind_test_vectors(suite: CipherSuite, SigOverride: SignatureScheme | null) {
	const {
		BlindBbs,
		Bbs: {
			serialize,
			hash_to_scalar,
			create_generators,
		},
		params: { curves: { G1 } },
	} = suite;
	const {
		api_id,
		BlindSign,
		Commit,
		CommitInit,
		CommitFinalize,
		BlindProofGen,
		BlindProofGenInit,
		BlindProofGenFinalize,
	} = BlindBbs;
	const Sig = SigOverride || BlindBbs.Sig;

	const committed_messages = [
		fromHex("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"),
		fromHex("a75d8b634891af92282cc81a675972d1929d3149863c1fc0"),
		fromHex("835889a40744813a892eff9deb1edaeb"),
		fromHex("e1ca9729410dc6ba"),
		fromHex(""),
	];

	const keybind_private_keys_hash_dst = concat(toUtf8("TEST-VECTORS_"), api_id);
	const keybind_private_keys = [
		await hash_to_scalar(toUtf8("keybind_private_keys[0]"), keybind_private_keys_hash_dst),
		await hash_to_scalar(toUtf8("keybind_private_keys[1]"), keybind_private_keys_hash_dst),
		await hash_to_scalar(toUtf8("keybind_private_keys[2]"), keybind_private_keys_hash_dst),
	];
	const keybind_generators = [G1.Point.BASE, ...await create_generators(keybind_private_keys.length - 1, concat(toUtf8("KEYBIND_"), api_id))];
	const keybind_public_keys: PointG1[] = (
		keybind_private_keys
			.map((k, i) => keybind_generators[i].multiply(k))
	);
	const keybind_keypairs: [BufferSource, bigint][] = keybind_public_keys.map((k, i) => [serialize([k]), keybind_private_keys[i]]);

	const signature_description = SigOverride ? `

In \`Sig.Sign\`, the random nonce \`k~\` was computed deterministically as follows:
~~~
k~ = BBS.hash_to_scalar(
         BBS.serialize((SK, i)) || message,
         "TEST-VECTORS_${fromUtf8(api_id)}"
)
~~~
for \`Sig.Sign\` arguments \`SK\` and \`message\` as defined in (#scheme-definition),
and \`i\` an integer starting from 0 and incrementing until the signature succeeds.
This implementation is only for testing purposes and is not normative.
Implementations SHALL NOT interpret this as a recommended implementation.
` : "";
	const suite_description = `
Throughout this section, the elements of \`keybind_private_keys\` were computed as follows:

~~~
keybind_private_keys = [
	BBS.hash_to_scalar("keybind_private_keys[0]", "${fromUtf8(keybind_private_keys_hash_dst)}"),
	BBS.hash_to_scalar("keybind_private_keys[1]", "${fromUtf8(keybind_private_keys_hash_dst)}"),
	BBS.hash_to_scalar("keybind_private_keys[2]", "${fromUtf8(keybind_private_keys_hash_dst)}"),
]
~~~

The key binding generators are:
~~~
keybind_generators = [ BP1 ].append(BBS.create_generators(3, "KEYBIND_${fromUtf8(api_id)}"))
                   = ${format_list(2, keybind_generators.map(g => `h'${g.toHex()}'`))}
~~~
` + signature_description;

	async function generate_oneshot_commitment_test_vector(
		description: string,
		committed_messages: BufferSource[],
	): Promise<TestVectorCase> {
		const [commitment_with_proof, secret_prover_blind] = await Commit(committed_messages);

		return make_test_vector_case(
			description,
			`~~~
suite_id = "${suite.id}"
api_id = "${fromUtf8(api_id)}"
committed_messages = ${format_list(2, committed_messages.map(m => `h'${toHex(m)}'`))}

; (commitment_with_proof, secret_prover_blind) = Commit(committed_messages)
${wrap_string(2, `commitment_with_proof = h'${toHex(commitment_with_proof)}'`)}
secret_prover_blind = 0x${toHex(serialize([secret_prover_blind]))}
~~~
`);
	}

	async function generate_staged_commitment_test_vector(
		description: string,
		committed_messages: BufferSource[],
		keybind_keypairs: [BufferSource, bigint][],
	): Promise<TestVectorCase> {
		const keybind_public_keys: BufferSource[] = keybind_keypairs.map(([pk,]) => pk);
		const keybind_private_keys: bigint[] = keybind_keypairs.map(([, sk]) => sk);

		const [state, secret_prover_blind, challenge] = await CommitInit(committed_messages, keybind_public_keys);
		const keybind_signatures = await Promise.all(keybind_private_keys.map(
			(k, i) => Sig.Sign(keybind_generators[i], k, challenge)));
		const commitment_with_proof = await CommitFinalize(state, keybind_signatures);

		return make_test_vector_case(
			description,
			`~~~
suite_id = "${suite.id}"
api_id = "${fromUtf8(api_id)}"
committed_messages = ${format_list(2, committed_messages.map(m => `h'${toHex(m)}'`))}
keybind_private_keys = ${format_list(2, keybind_private_keys.map(k => `0x${toHex(serialize([k]))}`))}
keybind_public_keys = ${format_list(2, keybind_public_keys.map(k => `h'${toHex(k)}'`))}
K = ${keybind_public_keys.length}

; (state, secret_prover_blind, challenge) = CommitInit(committed_messages, keybind_public_keys)
${wrap_string(2, `state = h'${toHex(state)}'`)}
secret_prover_blind = 0x${toHex(serialize([secret_prover_blind]))}
challenge = h'${toHex(challenge)}'

; keybind_signatures[i] = Sig.Sign(keybind_generators[i], keybind_private_keys[i], challenge) for i in (0..(K-1))
keybind_signatures = ${format_list(2, keybind_signatures.map(s => `h'${toHex(s)}'`), true)}

; commitment_with_proof = CommitFinalize(state, keybind_signatures)
${wrap_string(2, `commitment_with_proof = h'${toHex(commitment_with_proof)}'`)}
~~~
`);
	}

	const commit_test_vectors = Promise.all([
		generate_oneshot_commitment_test_vector(
			"Empty commitment",
			[],
		),

		generate_oneshot_commitment_test_vector(
			"Commitment with committed messages",
			committed_messages,
		),

		generate_staged_commitment_test_vector(
			"Commitment with key binding (K=1)",
			[], keybind_keypairs.slice(0, 1),
		),

		generate_staged_commitment_test_vector(
			"Commitment with committed messages and key binding (K=2)",
			committed_messages, keybind_keypairs.slice(0, 2),
		),
	]);

	// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-proof-test-vectors
	const SK = 0x60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fcn;
	const PK = fromHex(
		"a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa1" +
		"36f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d46" +
		"0acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63a" +
		"ebc364cd55ded0c"
	);
	const header = fromHex("11223344556677889900aabbccddeeff");

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

	const presentation_header = fromHex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

	async function generate_commitless_signature_test_vector(
		description: string,
		messages: BufferSource[],
	): Promise<TestVectorCase> {
		const signature = await BlindSign(SK, PK, new Uint8Array(), header, messages);

		return make_test_vector_case(
			description,
			`~~~
suite_id = "${suite.id}"
api_id = "${fromUtf8(api_id)}"
SK = 0x${toHex(serialize([SK]))}
${wrap_string(2, `PK = h'${toHex(serialize([PK]))}'`)}
header = h'${toHex(header)}'
messages = ${format_list(2, messages.map(m => `h'${toHex(m)}'`))}

; signature = BlindSign(SK, PK, h'', header, messages)
${wrap_string(2, `signature = h'${toHex(signature)}'`)}
~~~
`);
	}

	async function generate_oneshot_signature_test_vector(
		description: string,
		committed_messages: BufferSource[],
		messages: BufferSource[],
	): Promise<TestVectorCase> {
		const [commitment_with_proof, secret_prover_blind] = await Commit(committed_messages);
		const signature = await BlindSign(SK, PK, commitment_with_proof, header, messages);

		return make_test_vector_case(
			description,
			`~~~
suite_id = "${suite.id}"
api_id = "${fromUtf8(api_id)}"
SK = 0x${toHex(serialize([SK]))}
${wrap_string(2, `PK = h'${toHex(serialize([PK]))}'`)}
header = h'${toHex(header)}'
committed_messages = ${format_list(2, committed_messages.map(m => `h'${toHex(m)}'`))}
messages = ${format_list(2, messages.map(m => `h'${toHex(m)}'`))}

; (commitment_with_proof, secret_prover_blind) = Commit(committed_messages)
${wrap_string(2, `commitment_with_proof = h'${toHex(commitment_with_proof)}'`)}

; signature = BlindSign(SK, PK, commitment_with_proof, header, messages)
${wrap_string(2, `signature = h'${toHex(signature)}'`)}
~~~
`);
	}

	async function generate_staged_signature_test_vector(
		description: string,
		committed_messages: BufferSource[],
		keybind_keypairs: [BufferSource, bigint][],
		messages: BufferSource[],
	): Promise<TestVectorCase> {
		const keybind_public_keys: BufferSource[] = keybind_keypairs.map(([pk,]) => pk);
		const keybind_private_keys: bigint[] = keybind_keypairs.map(([, sk]) => sk);

		const [state, secret_prover_blind, challenge] = await CommitInit(committed_messages, keybind_public_keys);
		const keybind_signatures = await Promise.all(keybind_private_keys.map((dsk, i) =>
			Sig.Sign(keybind_generators[i], dsk, challenge)
		));
		const commitment_with_proof = await CommitFinalize(state, keybind_signatures);
		const signature = await BlindSign(SK, PK, commitment_with_proof, header, messages);

		return make_test_vector_case(
			description,
			`~~~
suite_id = "${suite.id}"
api_id = "${fromUtf8(api_id)}"
SK = 0x${toHex(serialize([SK]))}
${wrap_string(2, `PK = h'${toHex(serialize([PK]))}'`)}
header = h'${toHex(header)}'
committed_messages = ${format_list(2, committed_messages.map(m => `h'${toHex(m)}'`))}
messages = ${format_list(2, messages.map(m => `h'${toHex(m)}'`))}
keybind_private_keys = ${format_list(2, keybind_private_keys.map(k => `0x${toHex(serialize([k]))}`))}
keybind_public_keys = ${format_list(2, keybind_public_keys.map(k => `h'${toHex(k)}'`))}
K = ${keybind_public_keys.length}

; (state, secret_prover_blind, challenge) = CommitInit(committed_messages, keybind_public_keys)
; keybind_signatures[i] = Sig.Sign(keybind_generators[i], keybind_private_keys[i], challenge) for i in (0..(K-1))
; commitment_with_proof = CommitFinalize(state, keybind_signatures)
${wrap_string(2, `commitment_with_proof = h'${toHex(commitment_with_proof)}'`)}

; signature = BlindSign(SK, PK, commitment_with_proof, header, messages)
${wrap_string(2, `signature = h'${toHex(signature)}'`)}
~~~
`);
	}


	const signature_test_vectors = Promise.all([
		generate_commitless_signature_test_vector("Signature with no commitment or messages", []),
		generate_commitless_signature_test_vector("Signature with no commitment", messages),

		generate_oneshot_signature_test_vector(
			"Signature with empty commitment and no signer messages",
			[], [],
		),
		generate_oneshot_signature_test_vector(
			"Signature with committed messages and no signer messages",
			committed_messages, [],
		),
		generate_oneshot_signature_test_vector(
			"Signature with empty commitment and some signer messages",
			[], messages,
		),
		generate_oneshot_signature_test_vector(
			"Signature with committed messages and signer messages",
			committed_messages, messages,
		),

		generate_staged_signature_test_vector(
			"Signature with committed messages and key binding (K=1) but no signer messages",
			committed_messages, keybind_keypairs.slice(0, 1), [],
		),
		generate_staged_signature_test_vector(
			"Signature with committed messages, key binding (K=3) and signer messages",
			committed_messages, keybind_keypairs, messages,
		),
	]);

	async function generate_oneshot_proof_test_vector(
		description: string,
		committed_messages: BufferSource[],
		messages: BufferSource[],
		message_disclosures: DisclosureChoice[],
	): Promise<TestVectorCase> {
		const [commitment_with_proof, secret_prover_blind] = await Commit(committed_messages);
		const signature = await BlindSign(SK, PK, commitment_with_proof, header, messages);
		const [proof, add_zkp_info] = await BlindProofGen(
			PK,
			signature,
			header,
			presentation_header,
			[...messages, ...committed_messages],
			messages.length,
			message_disclosures,
			secret_prover_blind,
		);

		return make_test_vector_case(
			description,
			`~~~
suite_id = "${suite.id}"
api_id = "${fromUtf8(api_id)}"
SK = 0x${toHex(serialize([SK]))}
${wrap_string(2, `PK = h'${toHex(serialize([PK]))}'`)}
header = h'${toHex(header)}'
presentation_header = h'${toHex(presentation_header)}'
messages = ${format_list(2, messages.map(m => `h'${toHex(m)}'`))}
committed_messages = ${format_list(2, committed_messages.map(m => `h'${toHex(m)}'`))}
message_disclosures = ${format_list(2, message_disclosures.map(d => `"${d}"`))}

; (commitment_with_proof, secret_prover_blind) = Commit(committed_messages)
; signature = BlindSign(SK, PK, commitment_with_proof, header, messages)
${wrap_string(2, `signature = h'${toHex(signature)}'`)}
secret_prover_blind = 0x${toHex(serialize([secret_prover_blind]))}

; (proof, add_zkp_info) = BlindProofGen(PK, signature, header, presentation_header, messages.append(committed_messages), length(messages), message_disclosures, secret_prover_blind)
${wrap_string(2, `proof = h'${toHex(proof)}'`)}
add_zkp_info = [
  ${format_list(4, add_zkp_info[0].map(s => `0x${toHex(serialize([s]))}`))},
  ${format_list(4, add_zkp_info[1].map(s => `0x${toHex(serialize([s]))}`))},
]
~~~
`);
	}

	async function generate_staged_proof_test_vector(
		description: string,
		committed_messages: BufferSource[],
		keybind_keypairs: [BufferSource, bigint][],
		messages: BufferSource[],
		message_disclosures: DisclosureChoice[],
	): Promise<TestVectorCase> {
		const keybind_public_keys: BufferSource[] = keybind_keypairs.map(([pk,]) => pk);
		const keybind_private_keys: bigint[] = keybind_keypairs.map(([, sk]) => sk);

		const [state, secret_prover_blind, challenge] = await CommitInit(committed_messages, keybind_public_keys);
		const keybind_signatures = await Promise.all(keybind_private_keys.map((dsk, i) =>
			Sig.Sign(keybind_generators[i], dsk, challenge)
		));
		const commitment_with_proof = await CommitFinalize(state, keybind_signatures);
		const signature = await BlindSign(SK, PK, commitment_with_proof, header, messages);
		const [proof_state, add_zkp_info, keybind_challenges] = await BlindProofGenInit(
			PK,
			signature,
			header,
			presentation_header,
			[...messages, ...committed_messages],
			messages.length,
			message_disclosures,
			keybind_public_keys,
			secret_prover_blind,
		);
		const proof_keybind_signatures = await Promise.all(keybind_private_keys.map((dsk, i) =>
			Sig.Sign(keybind_generators[i], dsk, keybind_challenges[i])
		));
		const proof = await BlindProofGenFinalize(proof_state, proof_keybind_signatures);

		return make_test_vector_case(
			description,
			`~~~
suite_id = "${suite.id}"
api_id = "${fromUtf8(api_id)}"
SK = 0x${toHex(serialize([SK]))}
${wrap_string(2, `PK = h'${toHex(serialize([PK]))}'`)}
header = h'${toHex(header)}'
presentation_header = h'${toHex(presentation_header)}'
messages = ${format_list(2, messages.map(m => `h'${toHex(m)}'`))}
committed_messages = ${format_list(2, committed_messages.map(m => `h'${toHex(m)}'`))}
message_disclosures = ${format_list(2, message_disclosures.map(d => `"${d}"`))}
keybind_private_keys = ${format_list(2, keybind_private_keys.map(k => `0x${toHex(serialize([k]))}`))}
keybind_public_keys = ${format_list(2, keybind_public_keys.map(k => `h'${toHex(k)}'`))}
K = ${keybind_public_keys.length}

; (state, secret_prover_blind, challenge) = CommitInit(committed_messages, keybind_public_keys)
; keybind_signatures[i] = Sig.Sign(keybind_generators[i], keybind_private_keys[i], challenge) for i in (0..(K-1))
; commitment_with_proof = CommitFinalize(state, keybind_signatures)
; signature = BlindSign(SK, PK, commitment_with_proof, header, messages)
${wrap_string(2, `signature = h'${toHex(signature)}'`)}
secret_prover_blind = 0x${toHex(serialize([secret_prover_blind]))}

; (proof_state, add_zkp_info, keybind_challenges) = BlindProofGenInit(PK, signature, header, presentation_header, messages.append(committed_messages), length(messages), message_disclosures, keybind_public_keys, secret_prover_blind)
${wrap_string(2, `proof_state = h'${toHex(proof_state)}'`)}
add_zkp_info = [
  ${format_list(4, add_zkp_info[0].map(s => `0x${toHex(serialize([s]))}`))},
  ${format_list(4, add_zkp_info[1].map(s => `0x${toHex(serialize([s]))}`))},
]
keybind_challenges = ${format_list(2, keybind_challenges.map(s => `h'${toHex(s)}'`), true)}

; proof_keybind_signatures[i] = Sig.Sign(keybind_generators[i], keybind_private_keys[i], keybind_challenges[i]) for i in (0..(K-1))
proof_keybind_signatures = ${format_list(2, proof_keybind_signatures.map(s => `h'${toHex(s)}'`), true)}

; proof = BlindProofGenFinalize(proof_state, proof_keybind_signatures)
${wrap_string(2, `proof = h'${toHex(proof)}'`)}
~~~
`);
	}

	const disclosure_choices: DisclosureChoice[] = ["DISCLOSE", "COMMIT", "HIDE"];

	const proof_test_vectors = Promise.all([
		generate_oneshot_proof_test_vector(
			"Proof with empty commitment and no signer messages",
			[], [], [],
		),
		generate_oneshot_proof_test_vector(
			"Proof with all committed messages disclosed and no signer messages",
			committed_messages, [], committed_messages.map(() => "DISCLOSE"),
		),
		generate_oneshot_proof_test_vector(
			"Proof with all committed messages committed and no signer messages",
			committed_messages, [], committed_messages.map(() => "COMMIT"),
		),
		generate_oneshot_proof_test_vector(
			"Proof with all committed messages hidden and no signer messages",
			committed_messages, [], committed_messages.map(() => "HIDE"),
		),
		generate_oneshot_proof_test_vector(
			"Proof with empty commitment and all signer messages disclosed",
			[], messages, messages.map(() => "DISCLOSE"),
		),
		generate_oneshot_proof_test_vector(
			"Proof with empty commitment and all signer messages committed",
			[], messages, messages.map(() => "COMMIT"),
		),
		generate_oneshot_proof_test_vector(
			"Proof with empty commitment and all signer messages hidden",
			[], messages, messages.map(() => "HIDE"),
		),
		generate_oneshot_proof_test_vector(
			"Proof with all committed messages and signer messages disclosed",
			committed_messages, messages, range(committed_messages.length + messages.length).map(() => "DISCLOSE"),
		),
		generate_oneshot_proof_test_vector(
			"Proof with all committed messages and signer messages committed",
			committed_messages, messages, range(committed_messages.length + messages.length).map(() => "COMMIT"),
		),
		generate_oneshot_proof_test_vector(
			"Proof with all committed messages and signer messages hidden",
			committed_messages, messages, range(committed_messages.length + messages.length).map(() => "HIDE"),
		),
		generate_oneshot_proof_test_vector(
			"Proof with committed messages and signer messages disclosed, committed and hidden",
			committed_messages, messages, range(committed_messages.length + messages.length).map(i => disclosure_choices[i % disclosure_choices.length]),
		),

		generate_staged_proof_test_vector(
			"Key-bound (K=1) proof with no committed or signer messages",
			[], keybind_keypairs.slice(0, 1), [], [],
		),
		generate_staged_proof_test_vector(
			"Key-bound (K=2) proof with no committed or signer messages",
			[], keybind_keypairs.slice(0, 2), [], [],
		),
		generate_staged_proof_test_vector(
			"Key-bound (K=3) proof with no committed or signer messages",
			[], keybind_keypairs.slice(0, 3), [], [],
		),
		generate_staged_proof_test_vector(
			"Key-bound (K=1) proof with all committed messages disclosed and no signer messages",
			committed_messages, keybind_keypairs.slice(0, 1), [], committed_messages.map(() => "DISCLOSE"),
		),
		generate_staged_proof_test_vector(
			"Key-bound (K=2) proof with all committed messages committed and no signer messages",
			committed_messages, keybind_keypairs.slice(0, 2), [], committed_messages.map(() => "COMMIT"),
		),
		generate_staged_proof_test_vector(
			"Key-bound (K=3) proof with all committed messages hidden and no signer messages",
			committed_messages, keybind_keypairs.slice(0, 3), [], committed_messages.map(() => "HIDE"),
		),
		generate_staged_proof_test_vector(
			"Key-bound (K=3) proof with no committed messages and all signer messages disclosed",
			[], keybind_keypairs.slice(0, 3), messages, messages.map(() => "DISCLOSE"),
		),
		generate_staged_proof_test_vector(
			"Key-bound (K=2) proof with no committed messages and all signer messages committed",
			[], keybind_keypairs.slice(0, 2), messages, messages.map(() => "COMMIT"),
		),
		generate_staged_proof_test_vector(
			"Key-bound (K=1) proof with no committed messages and all signer messages hidden",
			[], keybind_keypairs.slice(0, 1), messages, messages.map(() => "HIDE"),
		),
		generate_staged_proof_test_vector(
			"Key-bound (K=1) proof with all committed messages and signer messages disclosed",
			committed_messages, keybind_keypairs.slice(0, 1), messages, range(committed_messages.length + messages.length).map(() => "DISCLOSE"),
		),
		generate_staged_proof_test_vector(
			"Key-bound (K=1) proof with all committed messages and signer messages committed",
			committed_messages, keybind_keypairs.slice(0, 1), messages, range(committed_messages.length + messages.length).map(() => "COMMIT"),
		),
		generate_staged_proof_test_vector(
			"Key-bound (K=2) proof with all committed messages and signer messages hidden",
			committed_messages, keybind_keypairs.slice(0, 2), messages, range(committed_messages.length + messages.length).map(() => "HIDE"),
		),
		generate_staged_proof_test_vector(
			"Key-bound (K=3) proof with committed messages and signer messages disclosed, committed and hidden",
			committed_messages, keybind_keypairs.slice(0, 3), messages, range(committed_messages.length + messages.length).map(i => disclosure_choices[i % disclosure_choices.length]),
		),
	]);

	return {
		suite_id: suite.id,
		suite_description,
		subsections: [
			{ title: "Commitment", test_cases: await commit_test_vectors },
			{ title: "Signature", test_cases: await signature_test_vectors },
			{ title: "Proof", test_cases: await proof_test_vectors },
		],
	};
}

async function generate_test_vectors() {
	const suites = await Promise.all(keybindSuites.map(async ({ suiteId, SigConstructor }) => {
		const suite = getCipherSuite(
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

		// await generate_non_keybind_test_vectors(suite);
		return generate_keybind_test_vectors(suite, SigConstructor ? SigConstructor(suite) : null);
	}));

	for (const suite of suites) {
		console.log(`## \`${suite.suite_id}\`

${suite.suite_description}
`);

		for (const subsection of suite.subsections) {
			console.log(`### ${subsection.title}

`);

			for (const test_case of subsection.test_cases) {
				console.log(`#### ${test_case.title}

${test_case.content}
`);
			}
		}
	}
}

generate_test_vectors();
