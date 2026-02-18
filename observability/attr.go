package observability

import (
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/unicitynetwork/bft-go-base/types"
)

func Round(round uint64) attribute.KeyValue {
	return attribute.Int64("round", int64(round)) /* #nosec G115 its unlikely that value of round exceeds int64 max value */
}

func Partition(id types.PartitionID) attribute.KeyValue {
	return attribute.Int("partition", int(id))
}

func Shard(partition types.PartitionID, shard types.ShardID, extra ...attribute.KeyValue) metric.MeasurementOption {
	return metric.WithAttributeSet(attribute.NewSet(
		append(
			extra,
			attribute.Int64("partition", int64(partition)),
			attribute.String("shard", shard.String()),
		)...,
	))
}

/*
ErrStatus returns attribute named "status" with value "ok" if the param
err is nil and "err" when it is not.
*/
func ErrStatus(err error) attribute.KeyValue {
	status := "ok"
	if err != nil {
		status = "err"
	}
	return attribute.String("status", status)
}
