/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * vimc-streamer.h Virtual Media Controller Driver
 *
 * Copyright (C) 2018 Lucas A. M. Magalhães <lucmaga@gmail.com>
 *
 */

#ifndef _VIMC_STREAMER_H_
#define _VIMC_STREAMER_H_

#include <media/media-device.h>

#include "vimc-common.h"

#define VIMC_STREAMER_PIPELINE_MAX_SIZE 16

<<<<<<< HEAD:drivers/media/test-drivers/vimc/vimc-streamer.h
/**
 * struct vimc_stream - struct that represents a stream in the pipeline
 *
 * @pipe:		the media pipeline object associated with this stream
 * @ved_pipeline:	array containing all the entities participating in the
 * 			stream. The order is from a video device (usually a
 *			capture device) where stream_on was called, to the
 *			entity generating the first base image to be
 *			processed in the pipeline.
 * @pipe_size:		size of @ved_pipeline
 * @kthread:		thread that generates the frames of the stream.
 *
 * When the user call stream_on in a video device, struct vimc_stream is
 * used to keep track of all entities and subdevices that generates and
 * process frames for the stream.
 */
=======
>>>>>>> master:drivers/media/platform/vimc/vimc-streamer.h
struct vimc_stream {
	struct media_pipeline pipe;
	struct vimc_ent_device *ved_pipeline[VIMC_STREAMER_PIPELINE_MAX_SIZE];
	unsigned int pipe_size;
<<<<<<< HEAD:drivers/media/test-drivers/vimc/vimc-streamer.h
	struct task_struct *kthread;
};

=======
	u8 *frame;
	struct task_struct *kthread;
};

/**
 * vimc_streamer_s_streamer - start/stop the stream
 *
 * @stream:	the pointer to the stream to start or stop
 * @ved:	The last entity of the streamer pipeline
 * @enable:	any non-zero number start the stream, zero stop
 *
 */
>>>>>>> master:drivers/media/platform/vimc/vimc-streamer.h
int vimc_streamer_s_stream(struct vimc_stream *stream,
			   struct vimc_ent_device *ved,
			   int enable);

#endif  //_VIMC_STREAMER_H_
