import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { OnInit } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { VulnerabilityService } from '../vulnerability.service';
import { HttpHeaders, HttpErrorResponse } from '@angular/common/http';
import { Observable } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { CveTableComponent } from "../cve-table/cve-table.component";

@Component({
    selector: 'app-home',
    standalone: true,
    templateUrl: './home.component.html',
    styleUrl: './home.component.css',
    imports: [
        CommonModule,
        CveTableComponent
    ]
})

export class HomeComponent {
  //data: any;

  vulnerabilities: any[] = [];

  constructor(private vulnerabilityService: VulnerabilityService) { }

  //constructor(private http: HttpClient, private vulnerabilityService: VulnerabilityService) {}

  ngOnInit(): void {
    this.getCves();
  }

  getCves(): void {
    this.vulnerabilityService.getCves()
      .subscribe(data => {
        this.vulnerabilities = data.result.CVE_Items;
      });
  }

  // constructor(private http: HttpClient) { }

  // ngOnInit(): void {
  //   const headers = new HttpHeaders().set('Max-Redirects', '0');
  
  //   this.http.get<any>('https://services.nvd.nist.gov/rest/json/cves/2.0/', { headers })
  //     .pipe(
  //       catchError((error: HttpErrorResponse) => {
  //         if (error.status === 301 || error.status === 302) {
  //           console.error('Redirection HTTP détectée.');
  //           return new Observable<never>();
  //         }
  //         return new Observable<never>();
  //       })
  //     )
  //     .subscribe(data => {
  //       // Filtrer et transformer les données si nécessaire
  //       this.vulnerabilities = data.result.CVE_Items;
  //     });
  // }

  //constructor(private vulnerabilityService: VulnerabilityService) { }
/*
  fetchVulnerabilities(params: any): void {
    this.vulnerabilityService.getVulnerabilities(params)
      .subscribe((data: any) => {
        this.vulnerabilities = data.vulnerabilities;
      }, (error) => {
        console.error('Error fetching vulnerabilities:', error);
      });
  } */

}
