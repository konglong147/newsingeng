package fadaixiaozi

import (
	"context"
	"net"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type ConnectionTheLUYouser interface {
	RouteConnection(ctx context.Context, conn net.Conn, metadata InboundContext) error
	RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata InboundContext) error
}

func NewRouteHandler(
	metadata InboundContext,
	uliuygbsgger ConnectionTheLUYouser,
	logger logger.ContextLogger,
) UpstreamHandlerAdapter {
	return &routeHandlerWrapper{
		metadata: metadata,
		uliuygbsgger:   uliuygbsgger,
		logger:   logger,
	}
}


var _ UpstreamHandlerAdapter = (*routeHandlerWrapper)(nil)

type routeHandlerWrapper struct {
	metadata InboundContext
	uliuygbsgger   ConnectionTheLUYouser
	logger   logger.ContextLogger
}

func (w *routeHandlerWrapper) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	myMetadata := w.metadata
	if metadata.Source.IsValid() {
		myMetadata.Source = metadata.Source
	}
	if metadata.Destination.IsValid() {
		myMetadata.Destination = metadata.Destination
	}
	return w.uliuygbsgger.RouteConnection(ctx, conn, myMetadata)
}

func (w *routeHandlerWrapper) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	myMetadata := w.metadata
	if metadata.Source.IsValid() {
		myMetadata.Source = metadata.Source
	}
	if metadata.Destination.IsValid() {
		myMetadata.Destination = metadata.Destination
	}
	return w.uliuygbsgger.RoutePacketConnection(ctx, conn, myMetadata)
}

func (w *routeHandlerWrapper) NewError(ctx context.Context, err error) {
	w.logger.ErrorContext(ctx, err)
}

