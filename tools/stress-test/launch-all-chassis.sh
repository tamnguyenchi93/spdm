#!/bin/bash

REQUEST_FOLDER=${1:-requests}
ITERATIONS=${2:-1}
HMC_HOST=${3:-localhost}
HMC_PORT=${4:-3122}

CHASSIS=("HGX_ERoT_FPGA_0" \
    "HGX_ERoT_GPU_SXM_1" \
    "HGX_ERoT_GPU_SXM_2" \
    "HGX_ERoT_GPU_SXM_3" \
    "HGX_ERoT_GPU_SXM_4" \
    "HGX_ERoT_GPU_SXM_5" \
    "HGX_ERoT_GPU_SXM_6" \
    "HGX_ERoT_GPU_SXM_7" \
    "HGX_ERoT_GPU_SXM_8" \
    "HGX_ERoT_BMC_0" \
    "HGX_ERoT_NVSwitch_0" \
    "HGX_ERoT_NVSwitch_1" \
    "HGX_ERoT_NVSwitch_2" \
    "HGX_ERoT_NVSwitch_3" \
    "HGX_ERoT_PCIeSwitch_0")
CPU_LOAD="top -bn1 | sed -n '2{p;q}' | cut -d% -f1 | sed 's/[^.0-9]//g'"

OUTPUT_DIR=output-$(date "+%F-%H-%M-%S")
rm -rf ${OUTPUT_DIR}
mkdir -p ${OUTPUT_DIR}

for CH in "${CHASSIS[@]}"; do
    mkdir -p ${OUTPUT_DIR}/${CH}
    for FILE in ./${REQUEST_FOLDER}/*.json; do
        AGGREGATE_RESULT=$(jq -nc \
            --arg StartTimestamp "$(date +"%s.%3N")" \
            --arg Iterations "0" \
            --arg AvgCPULoadStart "0" \
            --arg AvgCPULoadEnd "0" \
            --arg AvgDuration "0" \
            --argjson IterationResults "[ ]" \
            '$ARGS.named')
        for i in $(seq 1 ${ITERATIONS}); do
            echo "${CH} - ${FILE} - iteration ${i}"
            CPU_LOAD_START=$(sshpass -p 0penBmc ssh -p ${HMC_PORT} root@${HMC_HOST} ${CPU_LOAD})
            FULLNAME=$(basename -- "${FILE}")
            NAME="${FULLNAME%.*}"
            RESULT=$(./spdmtest.sh ${FILE} ${CH})
            CPU_LOAD_END=$(sshpass -p 0penBmc ssh -p ${HMC_PORT} root@${HMC_HOST} ${CPU_LOAD})
            RESULT=$(echo ${RESULT} | jq -S ". += { CPULoadStart:"${CPU_LOAD_START}", "CPULoadEnd":${CPU_LOAD_END} }")
            DURATION=$(echo ${RESULT} | jq -r ".Duration")

            PREV_ITERATIONS=$(echo ${AGGREGATE_RESULT} | jq -r ".Iterations")
            PREV_AVGCPULOADSTART=$(echo ${AGGREGATE_RESULT} | jq -r ".AvgCPULoadStart")
            PREV_AVGCPULOADEND=$(echo ${AGGREGATE_RESULT} | jq -r ".AvgCPULoadEnd")
            PREV_AVGDURATION=$(echo ${AGGREGATE_RESULT} | jq -r ".AvgDuration")
            NEW_ITERATIONS=$(echo "${PREV_ITERATIONS}+1" | bc)
            NEW_AVGCPULOADSTART=$(echo "${PREV_AVGCPULOADSTART}+${CPU_LOAD_START}" | bc)
            NEW_AVGCPULOADEND=$(echo "${PREV_AVGCPULOADEND}+${CPU_LOAD_END}" | bc)
            NEW_AVGDURATION=$(echo "${PREV_AVGDURATION}+${DURATION}" | bc)
            AGGREGATE_RESULT=$(echo ${AGGREGATE_RESULT} \
                | jq ".Iterations = ${NEW_ITERATIONS}" \
                | jq ".AvgCPULoadStart = ${NEW_AVGCPULOADSTART}" \
                | jq ".AvgCPULoadEnd = ${NEW_AVGCPULOADEND}" \
                | jq ".AvgDuration = ${NEW_AVGDURATION}" \
                | jq ".IterationResults += [ ${RESULT} ]")
        done
        ITERATIONS=$(echo ${AGGREGATE_RESULT} | jq ".Iterations")
        if [[ ${ITERATIONS} != "0" ]]; then
            AVGCPULOADSTART=$(echo ${AGGREGATE_RESULT} | jq -r ".AvgCPULoadStart")
            AVGCPULOADEND=$(echo ${AGGREGATE_RESULT} | jq -r ".AvgCPULoadEnd")
            AVGDURATION=$(echo ${AGGREGATE_RESULT} | jq -r ".AvgDuration")
            AVGCPULOADSTART=$(echo "${AVGCPULOADSTART}/${ITERATIONS}" | bc -l)
            AVGCPULOADEND=$(echo "${AVGCPULOADEND}/${ITERATIONS}" | bc -l)
            AVGDURATION=$(echo "${AVGDURATION}/${ITERATIONS}" | bc -l)
            AGGREGATE_RESULT=$(echo ${AGGREGATE_RESULT} \
                | jq ".AvgCPULoadStart = ${AVGCPULOADSTART}" \
                | jq ".AvgCPULoadEnd = ${AVGCPULOADEND}" \
                | jq ".AvgDuration = ${AVGDURATION}")
        fi
        printf "${AGGREGATE_RESULT}" > ${OUTPUT_DIR}/${CH}/${NAME}-output.json
    done
done
