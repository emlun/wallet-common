import { assert, describe, it } from "vitest";

import { fromHex, toHex } from "../utils/util";


describe("fromHex", () => {
	it("is the inverse of toHex.", async () => {
		const len = Math.round(128 * Math.random());
		const data = crypto.getRandomValues(new Uint8Array(len));
		assert.equal(toHex(data), toHex(fromHex(toHex(data))));
	});

	it("accepts uppercase and lowercase input.", async () => {
		const data = fromHex("aABbCc");
		assert.equal(toHex(data), "aabbcc");
	});

	it("ignores spaces.", async () => {
		const data = fromHex("aa bb cc");
		assert.equal(toHex(data), "aabbcc");
	});

	it("ignores newlines.", async () => {
		const data = fromHex(`
a
bb
ccc`);
		assert.equal(toHex(data), "abbccc");
	});

	it("ignores CRLF newlines.", async () => {
		const data = fromHex(`
a
bb
ccc`);
		assert.equal(toHex(data), "abbccc");
	});

	it("ignores tabs.", async () => {
		const data = fromHex("aa	bb	cc");
		assert.equal(toHex(data), "aabbcc");
	});
});
