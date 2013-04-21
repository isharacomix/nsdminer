# This file is part of NSDMiner
# Copyright 2011, 2012, North Carolina State University
# Please see the LICENSE file for terms of distribution
#
# Authors:
#   Barry Peddycord III <bwpeddyc@ncsu.edu>
#   Peng Ning <pning@ncsu.edu>

import re
import math

# This is a data structure that represents an NSDMiner Communication
# Graph.
class commgraph(object):

    # Initialize a commgraph using the output from NSDMiner, either
    # shared or exclusive mode.
    def __init__(self, fname=None):
        self.services = set()
        self.comment = ""
        
        # Here we dig through the file and build our graph.
        if fname:
            serv = None
            infile = open( fname )
            indata = infile.readlines()
            infile.close()
            self.comment = indata[0].strip()
            for l in indata:
                x = re.search("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+:[0-9]+:...",l)
                if x:
                    serv,count = l.strip().split()
                    serv = service( *serv.split(":") )
                    serv.weight = int(count)
                    self.services.add( serv )
                else:
                    x = re.search("^\\s+[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\\s+[0-9]+\\s.*$",l)
                    if x:
                        s = l.strip().split()
                        d = s[0]+":"+s[1]+":"+s[2]
                        serv.dependencies[d] = float(s[3])
                    else:
                        x = re.search("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+:[0-9]+:...",l)
                        if x:
                            serv,count = l.strip().split()
                            serv = service( *serv.split(":") )
                            serv.weight = int(count)
                            self.services.add( serv )
    
    # Prune all candidates with weights less than the specified value. Makes more
    # sense to do this after ranking.
    def prune( self, thresh ):
        g = self.copy()
        g.comment = g.comment +" -- Pruned to threshold of "+str(thresh)
        for s in g.services:
            for d in s.dependencies:
                kkills = []
                if s.dependencies[d] < thresh:
                    kkills.append(d)
            for d in kkills:
                s.dependencies.pop(d)
        return g
    
    # Rank dependency candidates. This sets all node weights to 100 and all edge
    # weights to a confidence value between 0 and 100. Lim is the minimum number
    # of edges for a service to matter.
    def rank( self, lim=50, log=True ):
        g = self.copy()
        if log:
            g.comment = g.comment+" -- "+" Log ranking with limit "+str(lim)
        else:
            g.comment = g.comment+" -- "+" Ratio ranking with limit "+str(lim)
        
        kills = []
        for s in g.services:
            if s.weight < lim:
                kills.append(s)
        for k in kills:
            g.services.discard(k)
        
        # Now rank.
        for s in g.services:
            A = s.weight*1.0
            for d in s.dependencies:
                B = s.dependencies[d]*1.0
                
                w = B/A
                if log:
                    try:    w = math.log(B,A)
                    except: w = 0                
                
                w *= 100
                w = max( min(100, w), 0 )
                s.dependencies[d] = w
            s.weight = 100
        
        return g
    
    # This identifies the similar services in your graph and creates
    # a list that you can pass to "apply sims", which will perform
    # the inference.
    # Simlist structure: [comment, simgroup1, simgroup2...]
    # Simgroup structure: [ [list of services], {common basis}]
    def identify_sims( self, similarity, agreement ):
    
        # Identify groups of similar services. We do a funky disjoint
        # set algorithm to take care of this to avoid dealing with
        # making graphs.
        simgroups = []
        pairs = []
        servs = set()
        for s1 in self.services:
            for s2 in self.services:
                if s1 > s2 and s1.sim(s2) >= similarity:
                    pairs.append( (s1, s2) )
                    servs.add(s1)
                    servs.add(s2)
        for p in pairs:
            s1,s2 = p

            if s1 in servs and s2 in servs:
                servs.discard(s1)
                servs.discard(s2)
                simgroups.append( [s1,s2] )
            elif s1 in servs:
                servs.discard(s1)
                for x in simgroups:
                    if s2 in x:
                        x.append(s1)
            elif s2 in servs:
                servs.discard(s2)
                for x in simgroups:
                    if s1 in x: x.append(s2)
            else:
                x,y = None, None
                for a in simgroups:
                    if s1 in a: x = a
                    if s2 in a: y = a
                if x != y:
                    a = x+y
                    simgroups.remove(x)
                    simgroups.remove(y)
                    simgroups.append(a)
        
        # Now, within these simgroups, we must find all of the services
        # in the basis. A service is in the basis if enough members of
        # the group depend on it.
        simgroups2 = []
        for s in simgroups:
            basis = {}
            for serv in s:
                for d in serv.dependencies:
                    if d not in basis:
                        count = 0.0
                        for k in s:
                            if d in k.dependencies:
                                count += 1.0
                        if count / len(s) > agreement:
                            basis[d] = serv.dependencies[d]*1.0/serv.weight*1.0
                    else:
                        basis[d]=max(basis[d],serv.dependencies[d]*1.0/serv.weight*1.0)
            simgroups2.append( [s, basis] )
        
        report = [ "Similarity "+str(similarity)+" | Agreement "+str(agreement) ]
        report += simgroups2
        return report
                   
    
    # This takes the similarity list produced by identify_sims and
    # splices them into the communication graph.
    def apply_sims( self, simlist ):
        g = self.copy()
        g.comment = g.comment + " -- "+ simlist[0]
        for l in simlist[1:]:
            depending, depended = l
            for s in depended:
                ratio = depended[s]
                for t in depending:
                    g.get(str(t)).dependencies[s] = t.weight * ratio
        return g
    
    
    # This identifies the clusters and saves them in a list to be applied
    # later, in a manner similar to the similarities above.
    def identify_clusters(self, support):
        clusters = []
        pairs = {}
        servs = set()
        for s in self.services:
            for s1 in s.dependencies:
                for s2 in s.dependencies:
                    if s1 > s2 and s1.split(":")[1:] == s2.split(":")[1:]:
                        if (s1,s2) in pairs:
                            pairs[(s1,s2)] += 1
                        else:
                            pairs[(s1,s2)] = 1
                        servs.add(s1)
                        servs.add(s2)
        kills = []
        for k in pairs:
            if pairs[k] < support:
                kills.append(k)
        for k in kills:
            pairs.pop(k)
        
        for p in pairs:
            s1,s2 = p

            if s1 in servs and s2 in servs:
                servs.discard(s1)
                servs.discard(s2)
                clusters.append( [s1,s2] )
            elif s1 in servs:
                servs.discard(s1)
                for x in clusters:
                    if s2 in x:
                        x.append(s1)
            elif s2 in servs:
                servs.discard(s2)
                for x in clusters:
                    if s1 in x: x.append(s2)
            else:
                x,y = None, None
                for a in clusters:
                    if s1 in a: x = a
                    if s2 in a: y = a
                if x != y:
                    a = x+y
                    clusters.remove(x)
                    clusters.remove(y)
                    clusters.append(a)
        return ["Clustering Support threshold "+str(support)] + clusters
        
    
    # This aggregates the clusters in the graph. Keep note of the members
    # of the clusters.
    def apply_clusters(self, clusters):
        g = self.copy()
        g.comment = g.comment +" -- "+clusters[0]
        clusters = clusters[1:]
        for s in g.services:
            mx = 0
            cluster = 0
            for c in clusters:
                cmax = 0
                cluster += 1
                kills = []
                serv = "cluster"+str(cluster) +":" + c[0].split(":")[1] +":"+ c[0].split(":")[2]
                for d in s.dependencies:
                    if d in c:
                        cmax = max( s.dependencies[d], cmax )
                        kills.append(d)
                if cmax > 0:
                    for k in kills:
                        s.dependencies.pop(k)
                    s.dependencies[serv] = cmax
        return g
    
    
    # Get the service from its canonical string.
    def get(self, string):
        ip,port,protocol = string.split(":")
        for s in self.services:
            if s.ip == ip and s.port == port and s.protocol == protocol:
                return s
        return None

    # Display the details of the commgraph.
    def __str__(self):
        l = list(self.services)
        l.sort()
        s = self.comment + "\n"
        for i in l:
            s += str(i)+" "+str(i.weight)+"\n"
            ll = []
            for j in i.dependencies:
                a,b,c = j.split(":")
                d = i.dependencies[j]
                ll.append((a,b,c,d))
            ll.sort(key=lambda x:x[3])
            ll.reverse()
            for (a,b,c,d) in ll:
                s += "    %-20s       % 5s  %3s    %10.3f\n"%(a,b,c,d)
            s += "\n"
        return s
    
    # Return a safe copy of this graph.
    def copy(self):
        g = commgraph()
        
        for s in self.services:
            g.services.add( s.copy() )
            
        g.comment = self.comment
        
        return g
        

# A commgraph contains a set of services.
class service(object):
    def __init__(self, ip, port, protocol, weight=0):
        self.ip = str(ip)
        self.port = str(port)
        self.protocol = str(protocol)
        self.weight = weight
        
        # This contains a canonical string, not an object.
        self.dependencies = {}
        
    # Return a safe copy of this service that won't mess things up.
    def copy(self):
        s = service( self.ip, self.port, self.protocol, self.weight )
        for d in self.dependencies:
            s.dependencies[d] = self.dependencies[d]
        return s
    
    # Checks whether the service contains a particular dependency.
    def has(self,service):
        return service in self.dependencies

    # Compares two services, putting them in a canonical order.
    def __cmp__(self,y):
        if type(y) is service:
            y = str(y)
        if type(y) is not str:
            raise TypeError
        return cmp(str(self), y)
    
    # Return the similarity between two services.
    def sim(self, y):
        if self.port != y.port:
            return 0
        
        l1 = len(self.dependencies) * 1.0
        l2 = len(y.dependencies) * 1.0
        l3 = 0
        for i in self.dependencies:
            if i in y.dependencies:
                l3+=1
        return 1.0*l3 / max(l1,l2)
    
    # Prints the canonical string.
    def __str__(self):
        return str(self.ip)+":"+str(self.port)+":"+str(self.protocol)
    def __repr__(self):
        return str(self.ip)+":"+str(self.port)+":"+str(self.protocol)

