#!/bin/bash

# 定义可执行文件和样例文件前缀
RUNTRACE="./runtrace"
TSH="./tsh"
TSHREF="./tshref"
TRACE_PREFIX="trace"
TRACE_COUNT=24

# 运行样例并保存输出
for i in $(seq -w 0 $TRACE_COUNT); do
    TRACE_FILE="${TRACE_PREFIX}${i}.txt"
    OUT_FILE="${TRACE_PREFIX}${i}.out"
    ANS_FILE="${TRACE_PREFIX}${i}.ans"

    # 使用 runtrace 运行样例并保存输出到 .out 文件
    if [ -f "$TRACE_FILE" ]; then
        $RUNTRACE "-f" "$TRACE_FILE" "-s" "$TSH" > "$OUT_FILE"
    else
        echo "Trace file $TRACE_FILE not found!"
    fi

    # 使用 runtrace 运行样例并保存输出到 .ans 文件
    if [ -f "$TRACE_FILE" ]; then
        $RUNTRACE "-f" "$TRACE_FILE" "-s" "$TSHREF" > "$ANS_FILE"
    else
        echo "Trace file $TRACE_FILE not found!"
    fi
done

echo "All traces have been processed."