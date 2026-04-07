/**
 * QuarkDash Crypto SHAKE-256 Test
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.0.0
 * @author          Elijah Rastorguev
 * @build           1000
 * @website         https://dev.to/devsdaddy
 */
import {Shake256} from "../src";

/**
 * Shake-256 vector test
 */
test('SHAKE256 test vector', async () => {
    const input = new Uint8Array([0x00, 0x01, 0x02, 0x03]);
    const output = await Shake256.hash(input, 32);
    expect(output.length).toBe(32);
});