package online

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"zspure/config"
	"zspure/tasks"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

func SendOnlineRequest(url string) (string, error) {
	var html string
	var respHeaders map[string]interface{}

	if strings.Contains(url, "http://") || strings.Contains(url, "https://"){
		takeWebHttp(url, &html,&respHeaders, time.Second*time.Duration(config.TIMEOUT))
	} else {
		return "", fmt.Errorf("url must contains http:// or https://")
	}

	if err := tasks.DetectDeviceBaseURL(html, respHeaders); err != nil {
		return "", err
	}
	return html, nil
}

func takeWebHttp(url string, html *string, respHeaders *map[string]interface{}, timeout time.Duration) error {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"),
		chromedp.WindowSize(1920, 1080),
		chromedp.Flag("headless", true),                  // run without UI
		chromedp.Flag("ignore-certificate-errors", true), // ignore TLS errors
	)

	// Create allocator context with these options
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	// Create a new Chrome context from the allocator context
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Optional: Add timeout to the context
	ctx, cancel = context.WithTimeout(ctx, timeout)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	var mu sync.Mutex
	var headersCaptured bool
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventResponseReceived:
			// Capture response headers for the main document
			if e.Type == network.ResourceTypeDocument && respHeaders != nil {
				mu.Lock()
				*respHeaders = e.Response.Headers
				headersCaptured = true
				mu.Unlock()
			}

		case *page.EventLifecycleEvent:
			// Wait for network idle to ensure most dynamic content is loaded
			if e, ok := ev.(*page.EventLifecycleEvent); ok && e.Name == "firstMeaningfulPaint" {
				if e.Name == "networkIdle" {
					wg.Done()
				}
				wg.Done()
			}
		}
	})

	errC := chromedp.Run(ctx,
		emulation.SetDeviceMetricsOverride(1920, 1080, 1.0, false),
		chromedp.Navigate(url),
		chromedp.ActionFunc(func(ctx context.Context) error {
			done := make(chan struct{})
			go func() {
				wg.Wait()
				close(done)
			}()
			select {
			case <-done:
				return nil
			case <-time.After(timeout):
				return fmt.Errorf("timeout waiting for firstMeaningfulPaint")
			}
		}),
		chromedp.WaitReady("body"),
		chromedp.OuterHTML("html", html),
	)
	if errC != nil {
		return errC
	}
	if respHeaders != nil && !headersCaptured {
		return fmt.Errorf("failed to capture response headers for %s", url)
	}
	return nil
}

func takeWebHttps(url string, html *string, respHeaders *map[string]interface{}, timeout time.Duration) error {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"),
		chromedp.WindowSize(1920, 1080),
		chromedp.Flag("headless", true),                  // run without UI
		chromedp.Flag("ignore-certificate-errors", true), // ignore TLS errors
	)

	// Create allocator context with these options
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	// Create a new Chrome context from the allocator context
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Optional: Add timeout to the context
	ctx, cancel = context.WithTimeout(ctx, timeout)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	var mu sync.Mutex
	var headersCaptured bool
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventResponseReceived:
			// Capture response headers for the main document
			if e.Type == network.ResourceTypeDocument && respHeaders != nil {
				mu.Lock()
				*respHeaders = e.Response.Headers
				headersCaptured = true
				mu.Unlock()
			}
		case *page.EventLifecycleEvent:
			// Wait for network idle to ensure most dynamic content is loaded
			if e, ok := ev.(*page.EventLifecycleEvent); ok && e.Name == "firstMeaningfulPaint" {
				if e.Name == "networkIdle" {
					wg.Done()
				}
				wg.Done()
			}
		}
	})

	err := chromedp.Run(ctx,
		emulation.SetDeviceMetricsOverride(1920, 1080, 1.0, false),
		chromedp.Navigate(url),
		chromedp.ActionFunc(func(ctx context.Context) error {
			done := make(chan struct{})
			go func() {
				wg.Wait()
				close(done)
			}()
			select {
			case <-done:
				return nil
			case <-time.After(timeout):
				return fmt.Errorf("timeout waiting for firstMeaningfulPaint")
			}
		}),
		chromedp.OuterHTML("html", html),
	)
	if err != nil {
		return err
	}
	if respHeaders != nil && !headersCaptured {
		return fmt.Errorf("failed to capture response headers for %s", url)
	}

	return nil
}
