from collections import namedtuple
import struct
import os.path

PboFileEntry = namedtuple('PboFileEntry', ['filename', 'method', 'orig_size', 'timestamp', 'size'])
PBO_HEADER_FMT_STR = '<IIIII'

def decode_pbo_header_entry(s, fname_start, fname_end):
    fname = s[fname_start:fname_end]
    # start of header is one past the end of the string (to account for ASCII NULL char)
    struct_start = fname_end + 1
    struct_end  = struct_start + struct.calcsize(PBO_HEADER_FMT_STR)
    method, orig_size, reserved, timestamp, size = struct.unpack(PBO_HEADER_FMT_STR, s[struct_start:struct_end])
    return PboFileEntry(fname, method, orig_size, timestamp, size)

def read_pbo_header(file_map):
    m = file_map
    idx = 0
    pbo_header_entries = []
    while True:
        if m[idx] == '\0':
            return pbo_header_entries, idx+21
        
        new_idx = m.find('\0', idx)

        if new_idx < 0:
            raise ValueError, 'Cannot decode pbo header; unexpected end of file'

        header = decode_pbo_header_entry(m, idx, new_idx)
        pbo_header_entries.append(header)


        idx = new_idx + struct.calcsize(PBO_HEADER_FMT_STR) + len('\0')
        
        
def expand_pbo(file_map, header_entries, basedir):
    # the sum of all the filename strings plus null termination, plus
    # a 20 byte structure for each entry, and finally a 21 byte
    # boundary before the file data.
    start_of_data = sum(len(e.filename) for e in header_entries) + 21*(len(header_entries)+1)
    basedir = os.path.abspath(basedir)
    idx = start_of_data
    m = file_map
    for entry in header_entries:
        filename = os.path.abspath(os.path.join(basedir, entry.filename))
        dirname = os.path.dirname(filename)
        if os.path.exists(dirname):
            if not os.path.isdir(dirname):
                raise IOError("Given path %s exists but is not a directory" % dirname)
        else:
            os.makedirs(dirname)
        num_bytes = entry.size
        with open(filename, 'wb') as f:
            f.write(m[idx:idx+num_bytes])
            f.close()

