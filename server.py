from enum import IntEnum
import asyncio
import random
import struct

class SubpacketType(IntEnum):
	URL = 0x01,
	REFERER = 0x03,
	ID_PASS = 0x11,
	QUERY_FIELD = 0x22

class ResponseType(IntEnum):
	ALLOW = 0x10,
	DENY = 0x12,
	PASSWORD_REQUIRED = 0x21,
	UNK_23 = 0x23 # returns "image too large"

def mopera_subpacket(type, data):
	return struct.pack("<HB", len(data) + 3, type) + data

async def mopera_connect(reader, writer):
	# Parse mopera packet
	# TODO: What is unk1, unk2, unk3, unk4?
	hello_byte, header_size, message_type, total_length, unk1, unk2, unk3, unk4 = struct.unpack("<BBHIIIII", (await reader.read(24)))
	print(f"Received mopera packet of type {message_type}, size {total_length}:")
	total_length = total_length - 24
	packet_data = {}
	while total_length > 0:
		length, subtype = struct.unpack("<HB", (await reader.read(3)))
		data = await reader.read(length - 3)
		packet_data[subtype] = data
		print(f"- subtype {subtype}: {data}")
		total_length -= length

	response_type = ResponseType.ALLOW
	# TODO: What is this field used for?
	response = mopera_subpacket(SubpacketType.URL, struct.pack("<B", 0))

	writer.write(struct.pack("<BBHIIIII", 0x01, 0x18, response_type, 24 + len(response), unk1, unk2, unk3, unk4))
	writer.write(response)
	await writer.drain()
	writer.close()

async def run_mopera_server():
	server = await asyncio.start_server(mopera_connect, '0.0.0.0', 5555)
	async with server:
		await server.serve_forever()

asyncio.run(run_mopera_server())
