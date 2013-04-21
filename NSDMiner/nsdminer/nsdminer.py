# This file is part of NSDMiner
# Copyright 2011, 2012, North Carolina State University
# Please see the LICENSE file for terms of distribution
#
# Authors:
#   Barry Peddycord III <bwpeddyc@ncsu.edu>
#   Peng Ning <pning@nscu.edu>

# This is based on "NSDMiner: Automated Discovery of Network
# Service Dependencies" by Arun Natarajan, Peng Ning, Yao Liu,
# Sushil Jajodia, and Steve Hutchinson, presented at INFOCOM
# 2012.




import commgraph

# This creates a flow record from a string.
class flow(object):
    def __init__(self, s=None):
        if s is None:
            s = "0 0 0 TCP 127.0.0.1 0 127.0.0.1 0 ...... ...... 0 0 1"
        (start, end, dur, protocol, src_ip, src_port, dest_ip,
         dest_port, src_flags, dest_flags, packets, bytes, bi) = s.split()
        self.start = float(start)
        self.end = float(end)
        self.dur = float(dur)
        
        self.protocol = protocol
        self.src_ip = src_ip
        self.src_port = src_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        
        self.src_flags = src_flags
        self.dest_flags = dest_flags
        
        self.packets = int(packets)
        self.bytes = int(bytes)
        self.bi = False
        if bi == "2": self.bi = True
        
        self.passed = False
    
    # Returns true if 'f' is nested in this flow.
    def contains(self, f):
        if self.start <= f.start and self.end >= f.end and self.dest_ip == f.src_ip:
            return True
        else:
            return False
    
    # Return the service associated with the flow.
    def sv(self):
        return self.dest_ip + ":" + self.dest_port +":" + self.protocol

    def __str__(self):
        report = (str(self.start)+"\t"+str(self.end)+"\t"+str(self.dur)+"\t"+
                 str(self.protocol)+"\t"+str(self.src_ip)+"\t"+
                 str(self.src_port)+"\t"+str(self.dest_ip)+"\t"+
                 str(self.dest_port)+"\t"+str(self.src_flags)+"\t"+
                 str(self.dest_flags)+"\t"+str(self.packets)+"\t"+
                 str(self.bytes)+"\t")
        if self.bi: return report+"2"
        else: return report+"1"


# This reads a standard cisco v5 netflow file and returns a list of strings that can
# be passed to the flow record constructor.
def parse_ciscov5(fname):
    ifile = file( sys.argv[1], "rb" )
    idata = ifile.read()
    ifile.close()
    report = []
    
    # First, read the header.
    while( len(idata) > 0 ):
        header = idata[:24]
        idata = idata[24:]
        
        # Find the number of flows contained in this record.
        count = (ord(header[2])<<8) + ord(header[3])
        
        for i in range(0,count):
            record = idata[:48]
            idata = idata[48:]
            
            rec = flow()
            byt = []
            for c in record:
                byt.append( ord(c) )

            rec.src_ip = "%d.%d.%d.%d"%(byt[0], byt[1], byt[2], byt[3])
            rec.dest_ip = "%d.%d.%d.%d"%(byt[4], byt[5], byt[6], byt[7])

            rec.packets = (byt[16]<<24)+(byt[17]<<16)+(byt[18]<<8)+byt[19]
            rec.bytes = (byt[20]<<24)+(byt[21]<<16)+(byt[22]<<8)+byt[23]
            rec.start = (byt[24]<<24)+(byt[25]<<16)+(byt[26]<<8)+byt[27]
            rec.end = (byt[28]<<24)+(byt[29]<<16)+(byt[30]<<8)+byt[31]
            rec.src_port = (byt[32]<<8)+byt[33]
            rec.dest_port = (byt[34]<<8)+byt[35]
            
            a = ""
            
            if byt[37] & 32: a += "U"
            else: a += "."
            
            if byt[37] & 16: a += "A"
            else: a += "."
            
            if byt[37] &  8: a += "P"
            else: a += "."
            
            if byt[37] &  4: a += "R"
            else: a += "."
            
            if byt[37] &  2: a += "S"
            else: a += "."
            
            if byt[37] &  1: a += "F"
            else: a += "."
            
            rec.src_flags = a
            rec.dest_flags = a
            
            if byt[38] == 6: rec.protocol = "TCP"
            elif byt[38] == 17: rec.protocol = "UDP"
            else: rec.protocol = "..."
            
            rec.bi = True
            report.append( str(rec) )

# This builds and returns a commgraph from a series of flowfiles. Ensure
# that the flows are, in fact, in chronological order.
#   boolean shared: use shared mode
#   int limit: maximum number of flows to track. Set this to a high number
#              like 100000
#   list filt: a list of strings representing IP address filters. It's a
#              simple matcher that tries to match from the beginning of
#              the string. This is a whitelist.
def build_commgraph(shared, limit, filt, *files):
    g = commgraph.commgraph()
    oldest = 0.0
    newest = 0.0
    flowlist = []
    flowcount = 0
    for fname in files:
        f = file(fname)
        for l in f:
            if len(l.split()) == 13:
                newflow = flow(l)
                if newflow.bi and (newflow.protocol == "UDP" or
                                  (newflow.protocol == "TCP" and "S" in newflow.src_flags+newflow.dest_flags) ) and newflow.dur < 200:
                    if (oldest == 0): oldest = newflow.start
                    newest = newflow.end
                    flowcount += 1
                    
                    fpass = False
                    for y in filt:
                        if newflow.dest_ip.startswith(y):
                            fpass = True
                
                    # Find the nested flows.
                    kills = []
                    conflicts = []
                    for parent in flowlist:
                        if parent.end < newflow.start:
                            kills.append(parent)
                        elif parent.contains(newflow):
                            conflicts.append(parent)
                
                    # Remove "dead" flows.
                    for k in kills:
                        flowlist.remove(k)
                    if len(flowlist) > limit:
                        kills = flowlist - limit
                        while kills > 0:
                            flowlist.pop(0)
                            kills -= 1
                
                    # Deal with conflicts.
                    if len(conflicts) == 1:
                        serv = g.get( conflicts[0].sv() )
                        dep = newflow.sv()
                        if not serv.has(dep):
                            serv.dependencies[dep] = 0
                        serv.dependencies[dep] += 1
                    elif len(conflicts) > 1 and shared:
                        dep = newflow.sv()
                        for serv in conflicts:
                            serv = g.get( serv.sv() )
                            if not serv.has(dep):
                                serv.dependencies[dep] = 0
                            serv.dependencies[dep] += 1.0/len(conflicts)
                
                    # Only track services that fit the filter for dependencies.
                    if fpass or filt == []:
                        flowlist.append( newflow )
                        s = g.get( newflow.sv() )
                        if s is None:
                            g.services.add( commgraph.service( newflow.dest_ip,
                                            newflow.dest_port, newflow.protocol, 1 ))
                        else:
                            s.weight += 1
                
        f.close()
    
    kills = []
    for s in g.services:
        if len(s.dependencies) == 0:
            kills.append(s)
    for k in kills:
        g.services.discard(k)

    g.comment = "Flows from "+str(oldest)+" to "+str(newest)+" ("+str(flowcount)+" flows)"
    return g


# This combines flowfiles to reduce the false positive rate.
def combine_flows(target, limit, *files):
    outfile = file(target, "w")
    flows = []
    for fname in files:
        f = file(fname)
        for l in f:
            catch = False
            if len(l.split()) == 13:
                newflow = flow(l)
                for old in flows:
                    if (old.end == newflow.start and
                       old.protocol == newflow.protocol and
                       old.src_ip == newflow.src_ip and
                       old.dest_ip == newflow.dest_ip and
                       old.src_port == newflow.src_port and
                       old.dest_port == newflow.dest_port):
                        old.end = newflow.end
                        old.dur = old.end-old.start
                        old.bytes += newflow.bytes
                        old.packets += newflow.packets
                        if new.bi: old.bi = True
                        sk = ""
                        dk = ""
                        for c in "UAPRSF":
                            if c in old.src_flags or newflow.src_flags: sk += c
                            else:                                       sk += '.'
                            if c in old.dest_flags or newflow.dest_flags: dk += c
                            else:                                         dk += '.'
                        old.src_flags = sk
                        old.dest_flags = sk
                        old.passed = False
                        catch = True
            if not catch:
                flows.append(newflow)
        kills = []
        for old in flows:
            if old.passed:
                kills.append(old)
                outfile.write(str(old)+"\n")
            else: old.passed = True
        for k in kills:
            flows.remove(k)
    for old in flows:
        outfile.write(str(old)+"\n")
    outfile.close()
    os.system("sort -k 1,1 %s > %s.tmp"%(target,target))
    os.system("mv %s.tmp %s"%(target,target))

