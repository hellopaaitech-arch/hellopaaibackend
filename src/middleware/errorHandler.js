export function errorHandler(err, _req, res, _next) {
  const status = err?.statusCode || err?.status || 500;
  const message = err?.message || 'Internal Server Error';

  if (status >= 500) {
    // eslint-disable-next-line no-console
    console.error(err);
  }

  res.status(status).json({
    error: err?.name || 'Error',
    message
  });
}

