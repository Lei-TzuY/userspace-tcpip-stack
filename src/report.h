#ifndef REPORT_H
#define REPORT_H

/*
 * report.h — machine-readable export of the conversation table
 *
 * The human-readable summaries printed by the trackers are meant to be read.
 * These two writers are meant to be parsed: JSON for a script that wants the
 * whole structure, CSV for a spreadsheet or a quick sort by retransmission
 * count.
 *
 * Both emit one record per direction of each TCP connection, because that is
 * the unit the analysis actually measures — a retransmission count for a
 * "connection" would have to hide which side did the retransmitting.
 */

#include "common.h"
#include "dispatch.h"

/*
 * Write the report to path, or to stdout when path is NULL or "-".
 *
 * packet_count is the number of packets read from the capture; the trackers do
 * not count packets they were not asked to look at, so it has to be passed in.
 *
 * Returns 0 on success, -1 if the file could not be opened or written.
 */
int report_write_json(const StackContext* ctx, const char* path,
                      size_t packet_count);
int report_write_csv(const StackContext* ctx, const char* path,
                     size_t packet_count);

#endif /* REPORT_H */
