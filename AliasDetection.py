#!/usr/bin/python3.6
# encoding:utf-8
from Definitions import Intersection
from AddrsToSeq import SeqToAddrs
from DynamicScan import Scan
import random

def AliasDetection(node_a, old_queue, new_queue, alias_queue, init_budget, budget, R, P, V, source_ip, active_file, target_file):
    """
    对异常结点进行别名前缀的检测，如确实发现别名前缀，
    则将前缀添加到集合P中；否则对其进行一次正常扫描后插入队列new_queue中

    Args：
        node_a：待检测的异常结点
        old_queue:待判断别名前缀存在性的结点队列
        new_queue：已经过判断的结点队列
        alias_queue：含有别名前缀的结点队列
        init_budget
        budget：扫描次数上限
        R：活跃地址集合
        P：别名前缀集合
        V：种子地址向量列表
        source_ip
        active_file
        target_file

    Return：
        budget:剩余扫描次数
    """

    probes = SelectProbes(node_a.TS, node_a.last_pop)
    budget -= len(probes)
    # if budget < 0:
    #     probes = LimitBudget(budget, probes)
    #     budget = -1
    with open(target_file, 'a', encoding='utf-8') as f:
        for target in probes:
            f.write(target + '\n')
    active_addrs = Scan(probes, source_ip, active_file)
    while active_addrs != set():    #!! 若至少有一个probe是活跃地址，就将TS做Expand并继续选取probe扫描?
                                    #!! 我认为应该是每一个子前缀下都至少有一个probe活跃才能继续
        delta = node_a.DS.pop()
        node_a.ExpandTS(delta, V)

        if node_a.parent.DS.stack == node_a.DS.stack:    # 树的向上迭代，用父结点替换其所有后代
            new_node = node_a.parent
            new_node.TS = node_a.TS
            retired = Intersection(new_node.childs, old_queue + new_queue)

            for retired_node in retired:
                new_node.SS = new_node.SS.union(retired_node.SS)
                new_node.NDA += retired_node.NDA

            old_remove = Intersection(retired, old_queue)
            new_remove = Intersection(retired, new_queue)
            alias_remove = Intersection(retired, alias_queue)
            for node in old_remove:
                old_queue.remove(node)
            for node in new_remove:
                new_queue.remove(node)
            for node in alias_remove:
                alias_queue.remove(node)

            new_node.AAD =float(new_node.NDA)/len(new_node.SS)
            node_a = new_node

        probes = SelectProbes(node_a.TS, node_a.last_pop)
        active_addrs = Scan(probes, source_ip, active_file)
        budget -= len(probes)
        with open(target_file, 'a', encoding='utf-8') as f:
            for target in probes:
                f.write(target + '\n')

    
    if node_a.isTSLarge() and node_a.isAbnormal(): #!! 此处用TS规模大于2^20以及式9的abnormal条件是否合理？
        prefixes = TranPrefix(node_a.TS)
        if prefixes.intersection(P) != prefixes:
            P.update(prefixes)
            alias_queue.append(node_a)
            for p in prefixes:
                print('[+]Alised prefix:{}'.format(p))

    else:   #!! 由于之前扫描probe时TS扩张的条件太过宽松，
            #!! 被判断为正常的结点由于目标空间过大，继续扫描时命中率会大幅降低
        C = TS_addr_union.difference(SS_addr_union) #本次需要扫描的地址集合
        budget -= len(C)
        if budget < 0:
            C = LimitBudget(budget, C)
            budget = 0
        with open(target_file, 'a', encoding='utf-8') as f:
            for target in C:
                f.write(target + '\n')
        active_addrs = Scan(C, source_ip, active_file)
        R.update(active_addrs)
        print('[+]Hit rate:{}   Remaining scan times:{}\n'
            .format(float(len(R)/(init_budget-budget)), budget))
        node_a.NDA += len(active_addrs)
        delta = node_a.DS.pop()
        node_a.SS = set(SeqToAddrs(node_a.TS))
        node_a.ExpandTS(delta, V)
        node_a.AAD = float(node_a.NDA) / len(node_a.SS)
        InsertNode(new_queue, node_a)

    # print('Over!')
    return budget


def SelectProbes(TS, last_pop_dim):
    """
    从结点的TS集合对应的地址空间中随机选取探针地址【示例见Fig.5】

    Args：
        TS：某异常结点的TS集合
        last_pop_dim：上一次从DS中pop的维度【从1开始】

    Return：
        probes：选取的探针地址集合
    """

    # pdb.set_trace()

    if TS == []:
        return set()

    probes = []
    vec_dim = len(TS[0])    #地址向量维数
    beta = int(2 ** (128/vec_dim))   #地址向量每一维度的基数
    for target in TS:
        target = target[:]
        for i in range(beta * 10):   # 选择beta的10倍个probe可以增加结果的可信度
            a_probe = []
            for pos in range(vec_dim):
                if pos == last_pop_dim - 1:
                    a_probe.append(i % beta)   #在上次被pop的维度上的值分别为0~beta-1
                elif target[pos] == -1:
                    a_probe.append(random.randint(0, beta - 1)) #在已被Expand的维度上有随机值
                else:
                    a_probe.append(target[pos]) #在其他维度上值与当前target相等
            probes.append(a_probe)
    
    probes = set(SeqToAddrs(probes))
    return probes


def TranPrefix(TS, last_pop_dim=0, last_pop_value=0):
    """
    从TS中提取公共前缀
    （第一个通配符维度及之后的所有维度均视作通配符）

    Args:
        TS：某结点的TS集合

    Return：
        得到的前缀字符串集合
    """

    # pdb.set_trace()
    # TS[last_pop_dim - 1] = last_pop_value   # 需要恢复上一次被误当作子网内容的前缀值
    
    vec_dim = len(TS[0])
    dim_len = int(128 / vec_dim) # 地址向量每一维度代表的二进制位数
    Expand = False
    prefixes = []
    prefixes_len = []   #记录各前缀的长度

    for vector in TS:
        a_prefix = []
        prefix_len = 128

        for dim in range(vec_dim):
            if vector[dim] == -1:
                Expand = True
            if Expand == True: # 前缀在通配维度上的值都为0
                prefix_len -= dim_len
                a_prefix.append(0)
            else:
                # prefix_len += 1
                a_prefix.append(vector[dim])
        prefixes.append(a_prefix)
        prefixes_len.append(prefix_len)
        Expand = False

    prefixes = SeqToAddrs(prefixes)

    for i in range(len(prefixes)):
        p = prefixes.pop(i)
        p = p + '/' + str(prefixes_len[i])
        prefixes.insert(i, p)

    return set(prefixes)


def InsertNode(queue, node):
    """
    将node按照AAD大小插入结点队列queue的正确位置

    Args:
        queue：结点队列
        node：待插入结点
    """

    _len = len(queue)
    i = 0
    while i < _len and queue[i].AAD > node.AAD:
        i += 1
    if i == _len:
        queue.append(node)
    else:
        queue.insert(i, node)

