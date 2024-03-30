import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { OnInit } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { VulnerabilityService } from '../vulnerability.service';

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [
    CommonModule
  ],
  templateUrl: './home.component.html',
  styleUrl: './home.component.css'
})
export class HomeComponent {
  data: any;

  vulnerabilities: any[] = [];

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
